"""Router /v1 cua Scan Engine."""

from __future__ import annotations

from fastapi import APIRouter

from ..engine.engine import scan_text
from ..engine.rules import get_ruleset
from ..models.schemas import (
    ActiveRule,
    ScanTextRequest,
    ScanTextResponse,
    Severity,
)

router = APIRouter(prefix="/v1")


@router.post(
    "/scan/text",
    response_model=ScanTextResponse,
    summary="Quet noi dung tin nhan / bai dang giao dich",
)
def post_scan_text(payload: ScanTextRequest) -> ScanTextResponse:
    data = scan_text(payload.text, payload.source)
    return ScanTextResponse(data=data)


@router.get(
    "/rules/active",
    response_model=list[ActiveRule],
    summary="Danh sach rule dang hoat dong (chi metadata, khong lo dieu kien)",
)
def get_active_rules() -> list[ActiveRule]:
    rs = get_ruleset()
    out: list[ActiveRule] = [
        ActiveRule(
            code=g.rule_code,
            name=g.rule_name,
            category="KEYWORD",
            weight=g.score,
            severity=Severity(g.severity),
        )
        for g in rs.keyword_groups
    ]
    out += [
        ActiveRule(
            code=r.code,
            name=r.name,
            category=r.category,
            weight=r.score,
            severity=Severity(r.severity),
        )
        for r in rs.rules
    ]
    return out
