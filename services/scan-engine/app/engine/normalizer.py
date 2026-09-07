"""Buoc 1 cua pipeline: chuan hoa van ban truoc khi match keyword.

Muc tieu: mot tin nhan lua dao viet "vi3tc0mb4nk" hay "VIETCOMBANK" hay
"vietcombank" deu phai roi vao cung mot dang de rule bat duoc.

Hai muc chuan hoa:
  normalize_light()  -> lowercase + bo dau tieng Viet
  normalize()        -> normalize_light + thay leetspeak (chi trong tu co chu cai)

So sanh ket qua hai ham nay chinh la cach phat hien "leet abuse":
neu ten thuong hieu chi xuat hien o ban normalize() ma khong co o ban
normalize_light() thi nguoi gui da co tinh viet bien the de ne rule.
"""

from __future__ import annotations

import re
import unicodedata

_LEET_TABLE = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "|": "i",
    }
)

_WHITESPACE_RE = re.compile(r"\s+")
_HAS_LETTER_RE = re.compile(r"[a-z]")


def strip_accents(text: str) -> str:
    """Bo dau tieng Viet: 'khoá' -> 'khoa', 'Đ' -> 'D'."""
    text = text.replace("đ", "d").replace("Đ", "D")
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


def normalize_light(text: str) -> str:
    """Lowercase + bo dau + gop khoang trang. KHONG dung leetspeak."""
    return _WHITESPACE_RE.sub(" ", strip_accents(text).lower()).strip()


def _deleet_token(token: str) -> str:
    """Chi thay so bang chu khi token co chua chu cai.

    Nho vay '100' hay '0912345678' giu nguyen, con 'vi3tc0mb4nk' moi bi
    doi thanh 'vietcombank'.
    """
    if _HAS_LETTER_RE.search(token):
        return token.translate(_LEET_TABLE)
    return token


def normalize(text: str) -> str:
    """Dang chuan hoa day du dung de match keyword va ten thuong hieu."""
    light = normalize_light(text)
    return " ".join(_deleet_token(tok) for tok in light.split(" "))
