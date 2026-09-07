"""Buoc 2 cua pipeline: trich xuat thuc the tu van ban goc.

Luon chay tren TEXT GOC (chua qua leetspeak) vi so dien thoai, so tai khoan
va so tien phai giu nguyen chu so that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .normalizer import normalize_light

# TLD hay gap - dung de tranh bat nham tu tieng Viet co dau cham vao URL.
_COMMON_TLDS = {
    "com", "net", "org", "vn", "info", "biz", "io", "co", "me", "cc", "us",
    "uk", "ru", "cn", "in", "app", "dev", "page", "site", "online", "shop",
    "store", "live", "click", "link", "top", "xyz", "tk", "ml", "ga", "cf",
    "gq", "icu", "buzz", "work", "asia", "pro", "fun", "space", "website",
}

_URL_RE = re.compile(
    r"\b(?:(?P<scheme>https?)://)?"
    r"(?P<host>(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
    r"(?P<path>[/?#][^\s]*)?",
    re.IGNORECASE,
)

_IP_URL_RE = re.compile(
    r"\b(?:https?://)?(?P<host>(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)

# Di dong VN: 0 + dau so (3,5,7,8,9) + 8 chu so. Chap nhan +84 / 84 dang truoc.
_PHONE_RE = re.compile(r"(?<![\d+])(?:\+?84|0)([35789]\d{8})(?!\d)")

_DIGITS_RE = re.compile(r"(?<!\d)\d{8,19}(?!\d)")

_AMOUNT_RE = re.compile(
    r"(?<![\w])\d[\d.,]*\s*"
    r"(?:k|nghin|nghìn|tr|trieu|triệu|ty|tỷ|ti|vnd|vnđ|đ|d)\b",
    re.IGNORECASE,
)

_OTP_RE = re.compile(
    r"(?:otp|ma xac thuc|ma xac minh|ma otp|ma pin|verification code)\D{0,25}(\d{4,8})",
    re.IGNORECASE,
)


@dataclass
class Entities:
    urls: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    bank_accounts: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    otp_codes: list[str] = field(default_factory=list)
    has_http_url: bool = False
    has_ip_host: bool = False


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _normalize_phone(nine_digits: str) -> str:
    return "+84" + nine_digits


def extract(text: str) -> Entities:
    ent = Entities()

    # --- URL dang IP (uu tien vi regex domain khong bat duoc) -------------
    ip_spans: list[tuple[int, int]] = []
    for m in _IP_URL_RE.finditer(text):
        host = m.group("host")
        octets = host.split(".")
        if all(o.isdigit() and int(o) <= 255 for o in octets):
            ent.urls.append(m.group(0))
            ent.hosts.append(host)
            ent.has_ip_host = True
            if m.group(0).lower().startswith("http://"):
                ent.has_http_url = True
            ip_spans.append(m.span())

    # --- URL dang domain --------------------------------------------------
    for m in _URL_RE.finditer(text):
        if any(s <= m.start() < e for s, e in ip_spans):
            continue
        host = m.group("host").lower().rstrip(".")
        tld = host.rsplit(".", 1)[-1]
        # Khong co scheme thi bat buoc TLD phai quen thuoc, tranh bat nham.
        if not m.group("scheme") and tld not in _COMMON_TLDS:
            continue
        ent.urls.append(m.group(0))
        ent.hosts.append(host)
        if (m.group("scheme") or "").lower() == "http":
            ent.has_http_url = True

    # --- So dien thoai ----------------------------------------------------
    phone_spans: list[tuple[int, int]] = []
    for m in _PHONE_RE.finditer(text):
        ent.phone_numbers.append(_normalize_phone(m.group(1)))
        phone_spans.append(m.span())

    # --- So tai khoan (chuoi so dai khong phai so dien thoai) -------------
    for m in _DIGITS_RE.finditer(text):
        if any(s <= m.start() < e for s, e in phone_spans):
            continue
        ent.bank_accounts.append(m.group(0))

    # --- So tien ----------------------------------------------------------
    for m in _AMOUNT_RE.finditer(text):
        ent.amounts.append(m.group(0).strip())

    # --- Ma OTP -----------------------------------------------------------
    for m in _OTP_RE.finditer(normalize_light(text)):
        ent.otp_codes.append(m.group(1))

    ent.urls = _dedupe(ent.urls)
    ent.hosts = _dedupe(ent.hosts)
    ent.phone_numbers = _dedupe(ent.phone_numbers)
    ent.bank_accounts = _dedupe(ent.bank_accounts)
    ent.amounts = _dedupe(ent.amounts)
    ent.otp_codes = _dedupe(ent.otp_codes)
    return ent
