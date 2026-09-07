"""Rule Engine - lo giai thich rui ro cua he thong.

Pipeline 7 buoc (theo thiet ke Week 3, muc 5.9 va 5.12):

    1. normalize      chuan hoa van ban
    2. extract        trich xuat URL / phone / so tai khoan / so tien / OTP
    3. keywords       match nhom tu khoa
    4. domains        phan tich ten mien
    5. facts          gom tat ca thanh mot tap FACT
    6. evaluate       chay rule tren tap FACT -> danh sach evidence
    7. score          cong diem, map muc canh bao, sinh khuyen nghi

Diem KHONG bao gio do mot mo hinh sinh ra: moi diem deu di kem mot ruleCode
tra nguoc ve duoc rules.json. Day la yeu cau "giai thich duoc" cua de tai.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from ..models.schemas import (
    Analysis,
    Evidence,
    ExtractedEntities,
    KeywordMatch,
    PatternMatch,
    Recommendation,
    RiskLevel,
    RiskResult,
    ScanTextData,
    Severity,
    Source,
    TextInputInfo,
)
from .extractor import Entities, extract
from .normalizer import normalize, normalize_light
from .rules import RuleSet, get_ruleset

_LEVEL_COLOR = {
    RiskLevel.SAFE: "GREEN",
    RiskLevel.CAUTION: "YELLOW",
    RiskLevel.DANGER: "RED",
}

_LEVEL_ACTION = {
    RiskLevel.SAFE: "ALLOW",
    RiskLevel.CAUTION: "VERIFY",
    RiskLevel.DANGER: "BLOCK",
}


# --------------------------------------------------------------------------
# Tien ich
# --------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_whitelisted(host: str, whitelist: tuple[str, ...]) -> bool:
    return any(host == w or host.endswith("." + w) for w in whitelist)


def _is_official(host: str, official: str) -> bool:
    return host == official or host.endswith("." + official)


# --------------------------------------------------------------------------
# Buoc 3: keyword
# --------------------------------------------------------------------------


def _match_keywords(normalized: str, rs: RuleSet) -> list[tuple[str, list[str]]]:
    """Tra ve [(ten_nhom, [tu khoa khop])] cho cac nhom co it nhat 1 tu khoa."""
    hits: list[tuple[str, list[str]]] = []
    for group in rs.keyword_groups:
        matched = [kw for kw in group.keywords if kw and kw in normalized]
        if matched:
            hits.append((group.name, matched))
    return hits


# --------------------------------------------------------------------------
# Buoc 4: ten mien
# --------------------------------------------------------------------------


def _analyse_domains(ent: Entities, rs: RuleSet) -> set[str]:
    facts: set[str] = set()
    if not ent.hosts:
        return facts

    whitelisted_count = 0
    for host in ent.hosts:
        if _is_whitelisted(host, rs.whitelist_domains):
            whitelisted_count += 1
            continue  # ten mien tin cay thi khong soi tiep

        tld = host.rsplit(".", 1)[-1]
        if tld in rs.suspicious_tlds:
            facts.add("URL_SUSPICIOUS_TLD")

        if any(host == s or host.endswith("." + s) for s in rs.shorteners):
            facts.add("URL_SHORTENER")

        leet_host = normalize(host)
        labels = [lb for lb in host.split(".") if lb != "www"]

        for brand, official in rs.brand_domains.items():
            if _is_official(host, official):
                break  # dung ten mien that cua thuong hieu -> khong phai gia mao
            # Ten thuong hieu lo ra sau khi go leetspeak: vietc0mbank -> vietcombank
            if brand in leet_host:
                facts.add("URL_TYPOSQUAT")
                break
            # Sai chinh ta co y: vietcornbank, vietcombamk...
            if len(brand) >= 5 and any(
                0 < _levenshtein(lb, brand) <= 2 for lb in labels
            ):
                facts.add("URL_TYPOSQUAT")
                break

    if whitelisted_count == len(ent.hosts):
        facts.add("URL_ALL_WHITELISTED")

    return facts


# --------------------------------------------------------------------------
# Buoc 5: gom FACT
# --------------------------------------------------------------------------


def _collect_facts(
    normalized: str,
    light: str,
    ent: Entities,
    keyword_hits: list[tuple[str, list[str]]],
    rs: RuleSet,
) -> set[str]:
    facts: set[str] = set()

    for group_name, _ in keyword_hits:
        facts.add(f"GROUP:{group_name}")

    for brand_fact, brands in rs.brand_groups.items():
        if any(b in normalized for b in brands):
            facts.add(brand_fact)

    # Co tinh viet bien the ten thuong hieu de ne bo loc?
    all_brands = {b for brands in rs.brand_groups.values() for b in brands}
    all_brands |= {normalize(b) for b in rs.brand_domains}
    if any(b in normalized and b not in light for b in all_brands):
        facts.add("LEET_BRAND")

    if ent.urls:
        facts.add("HAS_URL")
    if ent.has_http_url:
        facts.add("HAS_HTTP_URL")
    if ent.has_ip_host:
        facts.add("URL_IP_HOST")
    if ent.phone_numbers:
        facts.add("HAS_PHONE")
    if ent.bank_accounts:
        facts.add("HAS_BANK_ACCOUNT")
    if ent.amounts:
        facts.add("HAS_AMOUNT")
    if ent.otp_codes:
        facts.add("HAS_OTP")

    facts |= _analyse_domains(ent, rs)
    return facts


# --------------------------------------------------------------------------
# Buoc 7: diem, muc canh bao, khuyen nghi
# --------------------------------------------------------------------------


def _level_for(score: int, rs: RuleSet) -> RiskLevel:
    if score >= rs.danger_threshold:
        return RiskLevel.DANGER
    if score >= rs.caution_threshold:
        return RiskLevel.CAUTION
    return RiskLevel.SAFE


def _confidence(evidences: list[Evidence]) -> float:
    """Do chac chan cua ket luan.

    Chi tinh tren cac evidence LAM TANG diem - rule giam diem nhu
    URL_WHITELISTED khong duoc keo confidence xuong.
    """
    risky = [e for e in evidences if e.score > 0]
    if not risky:
        return 0.85
    value = 0.6 + 0.05 * len(risky)
    if any(e.severity == Severity.CRITICAL for e in risky):
        value += 0.1
    return round(min(value, 0.99), 2)


def _build_recommendation(
    level: RiskLevel,
    evidences: list[Evidence],
    pattern_codes: list[str],
    rs: RuleSet,
) -> Recommendation:
    template = None
    for code in pattern_codes:  # da sap xep theo diem giam dan
        if code in rs.recommendations:
            template = rs.recommendations[code]
            break
    if template is None:
        template = rs.recommendations["_default"][level.value]

    reasons = list(template["reasons"])
    for ev in evidences:
        if len(reasons) >= 6:
            break
        if ev.description and ev.description not in reasons:
            reasons.append(ev.description)

    return Recommendation(
        action=_LEVEL_ACTION[level],
        message=template["message"],
        reasons=reasons,
        next_steps=list(template["nextSteps"]),
    )


# --------------------------------------------------------------------------
# Diem vao
# --------------------------------------------------------------------------


def scan_text(text: str, source: Source = Source.OTHER) -> ScanTextData:
    started = time.perf_counter()
    rs = get_ruleset()

    light = normalize_light(text)
    normalized = normalize(text)
    ent = extract(text)
    keyword_hits = _match_keywords(normalized, rs)
    facts = _collect_facts(normalized, light, ent, keyword_hits, rs)

    evidences: list[Evidence] = []
    keyword_matches: list[KeywordMatch] = []

    # Evidence tu nhom tu khoa
    group_by_name = {g.name: g for g in rs.keyword_groups}
    for group_name, matched in keyword_hits:
        group = group_by_name[group_name]
        keyword_matches.append(
            KeywordMatch(category=group_name, keywords=matched, score=group.score)
        )
        evidences.append(
            Evidence(
                rule_code=group.rule_code,
                rule_name=group.rule_name,
                score=group.score,
                severity=Severity(group.severity),
                description=group.description,
            )
        )

    # Evidence tu rule suy dien / rule to hop
    pattern_matches: list[PatternMatch] = []
    matched_patterns: list[tuple[int, str]] = []
    for rule in rs.rules:
        if not rule.matches(facts):
            continue
        evidences.append(
            Evidence(
                rule_code=rule.code,
                rule_name=rule.name,
                score=rule.score,
                severity=Severity(rule.severity),
                description=rule.description,
            )
        )
        if rule.is_pattern:
            pattern_matches.append(
                PatternMatch(
                    pattern=rule.code,
                    description=rule.description,
                    score=rule.score,
                )
            )
            matched_patterns.append((rule.score, rule.code))

    evidences.sort(key=lambda e: e.score, reverse=True)
    matched_patterns.sort(reverse=True)

    risk_score = max(0, min(100, sum(e.score for e in evidences)))
    level = _level_for(risk_score, rs)

    return ScanTextData(
        scan_id=f"scan_text_{uuid.uuid4().hex[:12]}",
        input=TextInputInfo(text_length=len(text), source=source),
        result=RiskResult(
            risk_score=risk_score,
            risk_level=level,
            level_color=_LEVEL_COLOR[level],
            confidence=_confidence(evidences),
        ),
        analysis=Analysis(
            extracted_entities=ExtractedEntities(
                urls=ent.urls,
                phone_numbers=ent.phone_numbers,
                bank_accounts=ent.bank_accounts,
                amounts=ent.amounts,
                otp_codes=ent.otp_codes,
            ),
            keyword_matches=keyword_matches,
            pattern_matches=pattern_matches,
            matched_facts=sorted(facts),
        ),
        evidences=evidences,
        recommendation=_build_recommendation(
            level, evidences, [c for _, c in matched_patterns], rs
        ),
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        processing_time=int((time.perf_counter() - started) * 1000),
    )
