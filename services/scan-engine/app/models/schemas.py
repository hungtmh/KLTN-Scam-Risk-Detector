"""DTO cho Scan Engine.

Field trong Python dùng snake_case, JSON trả ra dùng camelCase đúng theo
document/Week2/02_Phan_Tich_Nghiep_Vu/API_Specification.md muc 2.2.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel

MAX_TEXT_LENGTH = 5000


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class Source(str, Enum):
    SMS = "SMS"
    ZALO = "ZALO"
    MESSENGER = "MESSENGER"
    EMAIL = "EMAIL"
    FACEBOOK = "FACEBOOK"
    OTHER = "OTHER"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DANGER = "DANGER"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# --------------------------------------------------------------------------
# Request
# --------------------------------------------------------------------------


class ScanTextRequest(CamelModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_LENGTH)
    source: Source = Source.OTHER
    save_history: bool = True

    @field_validator("text")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text khong duoc rong hoac chi chua khoang trang")
        return v


# --------------------------------------------------------------------------
# Response
# --------------------------------------------------------------------------


class ExtractedEntities(CamelModel):
    urls: list[str] = []
    phone_numbers: list[str] = []
    bank_accounts: list[str] = []
    amounts: list[str] = []
    otp_codes: list[str] = []


class KeywordMatch(CamelModel):
    category: str
    keywords: list[str]
    score: int


class PatternMatch(CamelModel):
    pattern: str
    description: str
    score: int


class Analysis(CamelModel):
    extracted_entities: ExtractedEntities
    keyword_matches: list[KeywordMatch] = []
    pattern_matches: list[PatternMatch] = []
    matched_facts: list[str] = []


class Evidence(CamelModel):
    rule_code: str
    rule_name: str
    score: int
    severity: Severity
    description: str | None = None
    source: Literal["rule", "llm"] = "rule"


class Recommendation(CamelModel):
    action: Literal["ALLOW", "VERIFY", "BLOCK"]
    message: str
    reasons: list[str] = []
    next_steps: list[str] = []


class RiskResult(CamelModel):
    risk_score: int
    risk_level: RiskLevel
    level_color: Literal["GREEN", "YELLOW", "RED"]
    confidence: float


class TextInputInfo(CamelModel):
    text_length: int
    source: Source


class ScanTextData(CamelModel):
    scan_id: str
    input: TextInputInfo
    result: RiskResult
    analysis: Analysis
    evidences: list[Evidence]
    recommendation: Recommendation
    scanned_at: str
    processing_time: int


class ScanTextResponse(CamelModel):
    success: bool = True
    data: ScanTextData


# --------------------------------------------------------------------------
# Error
# --------------------------------------------------------------------------


class ApiError(CamelModel):
    code: str
    message: str
    details: list[dict] | None = None


class ErrorResponse(CamelModel):
    success: bool = False
    error: ApiError


# --------------------------------------------------------------------------
# Rules (GET /v1/rules/active)
# --------------------------------------------------------------------------


class ActiveRule(CamelModel):
    code: str
    name: str
    category: str
    weight: int
    severity: Severity
