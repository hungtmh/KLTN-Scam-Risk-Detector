"""Nap va bieu dien bo rule.

Rule duoc mo ta hoan toan trong app/data/rules.json de sau nay bung thang
sang hai bang `risk_rules` / `rule_conditions` cua PostgreSQL ma khong phai
viet lai logic. Moi rule chi lam mot viec: so khop tap FACT do buoc phan tich
sinh ra.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .normalizer import normalize

RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.json"


@dataclass(frozen=True)
class KeywordGroup:
    name: str
    rule_code: str
    rule_name: str
    description: str
    severity: str
    score: int
    keywords: tuple[str, ...]  # da chuan hoa san


@dataclass(frozen=True)
class Rule:
    code: str
    name: str
    category: str
    description: str
    severity: str
    score: int
    requires_all: tuple[str, ...] = ()
    requires_any: tuple[str, ...] = ()
    requires_none: tuple[str, ...] = ()
    is_pattern: bool = False

    def matches(self, facts: set[str]) -> bool:
        if not all(f in facts for f in self.requires_all):
            return False
        if self.requires_any and not any(f in facts for f in self.requires_any):
            return False
        if any(f in facts for f in self.requires_none):
            return False
        return True


@dataclass(frozen=True)
class RuleSet:
    version: str
    caution_threshold: int
    danger_threshold: int
    keyword_groups: tuple[KeywordGroup, ...]
    brand_groups: dict[str, tuple[str, ...]]
    brand_domains: dict[str, str]
    whitelist_domains: tuple[str, ...]
    suspicious_tlds: frozenset[str]
    shorteners: tuple[str, ...]
    rules: tuple[Rule, ...]
    recommendations: dict = field(default_factory=dict)

    def rule_by_code(self, code: str) -> Rule | None:
        for r in self.rules:
            if r.code == code:
                return r
        return None


def _load(path: Path) -> RuleSet:
    raw = json.loads(path.read_text(encoding="utf-8"))

    groups = tuple(
        KeywordGroup(
            name=name,
            rule_code=cfg["ruleCode"],
            rule_name=cfg["ruleName"],
            description=cfg.get("description", ""),
            severity=cfg["severity"],
            score=int(cfg["score"]),
            # Chuan hoa keyword bang dung ham dung cho van ban -> hai ben
            # luon nam trong cung mot khong gian so sanh.
            keywords=tuple(normalize(k) for k in cfg["keywords"]),
        )
        for name, cfg in raw["keywordGroups"].items()
    )

    rules = tuple(
        Rule(
            code=r["code"],
            name=r["name"],
            category=r.get("category", "GENERAL"),
            description=r.get("description", ""),
            severity=r["severity"],
            score=int(r["score"]),
            requires_all=tuple(r.get("requiresAll", [])),
            requires_any=tuple(r.get("requiresAny", [])),
            requires_none=tuple(r.get("requiresNone", [])),
            is_pattern=bool(r.get("pattern", False)),
        )
        for r in raw["rules"]
    )

    return RuleSet(
        version=raw["version"],
        caution_threshold=int(raw["thresholds"]["caution"]),
        danger_threshold=int(raw["thresholds"]["danger"]),
        keyword_groups=groups,
        brand_groups={
            k: tuple(normalize(v) for v in vals)
            for k, vals in raw["brandGroups"].items()
        },
        brand_domains=dict(raw["brandDomains"]),
        whitelist_domains=tuple(d.lower() for d in raw["whitelistDomains"]),
        suspicious_tlds=frozenset(t.lower() for t in raw["suspiciousTlds"]),
        shorteners=tuple(s.lower() for s in raw["shorteners"]),
        rules=rules,
        recommendations=raw["recommendations"],
    )


@lru_cache(maxsize=1)
def get_ruleset() -> RuleSet:
    """Bo rule dang hoat dong. Cache lai vi doc file moi request la lang phi."""
    return _load(RULES_PATH)


def reload_ruleset() -> RuleSet:
    """Xoa cache va nap lai - dung khi sua rules.json luc dev."""
    get_ruleset.cache_clear()
    return get_ruleset()
