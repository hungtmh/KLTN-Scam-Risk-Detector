"""Test cho POST /v1/scan/text.

Cung bo case voi Postman collection trong postman/. Postman de demo bang tay,
pytest de chay tu dong trong CI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def scan(text: str, source: str = "SMS") -> dict:
    resp = client.post("/v1/scan/text", json={"text": text, "source": source})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    return body["data"]


# --------------------------------------------------------------------------
# 12 case nghiep vu
# --------------------------------------------------------------------------

CASES = [
    (
        "bank_impersonation",
        "THÔNG BÁO: Tài khoản của quý khách sắp bị khóa. Vui lòng xác minh "
        "ngay tại http://vietc0mbank.com hoặc gọi 0912345678",
        "DANGER",
    ),
    ("benign_chat", "Chào bạn, mai đi ăn cơm không?", "SAFE"),
    (
        "prize_scam",
        "Bạn đã trúng thưởng 100 triệu đồng! Vui lòng đóng phí 500k để nhận giải thưởng.",
        "DANGER",
    ),
    (
        "benign_link",
        "Đọc tin mới nhất tại https://vnexpress.net/kinh-doanh nhé bạn",
        "SAFE",
    ),
    (
        "leetspeak_brand",
        "Tài khoản vi3tc0mb4nk của bạn sắp bị khóa, vui lòng xác minh ngay",
        "DANGER",
    ),
    (
        "fake_shipper",
        "Shipper giao hàng nhanh đây, đơn của bạn cần thanh toán trước "
        "phí vận chuyển 35k vào STK 19001234567",
        "DANGER",
    ),
    (
        "fake_job",
        "Tuyển cộng tác viên làm việc tại nhà, không cần kinh nghiệm. "
        "Tạm ứng 200k để nhận nhiệm vụ đầu tiên",
        "DANGER",
    ),
    (
        "authority_threat",
        "Bộ Công an thông báo bạn liên quan vụ án, yêu cầu chuyển khoản gấp để xác minh",
        "DANGER",
    ),
    (
        "ip_host_and_bad_tld",
        "Nhấp vào http://185.23.44.9/login để nhận quà, hoặc https://vcb-verify.tk",
        "DANGER",
    ),
    (
        "otp_disclosure",
        "Mã OTP của bạn là 483920, vui lòng đọc cho nhân viên để xác minh",
        "CAUTION",
    ),
    ("shortener_only", "Xem ngay tại https://bit.ly/3xAbCd", "SAFE"),
    (
        "typosquat_domain",
        "Đăng nhập tại https://vietcornbank.com để nhận ưu đãi",
        "DANGER",
    ),
]


@pytest.mark.parametrize("name,text,expected", CASES, ids=[c[0] for c in CASES])
def test_risk_level(name: str, text: str, expected: str) -> None:
    data = scan(text)
    assert data["result"]["riskLevel"] == expected, (
        f'{name}: score={data["result"]["riskScore"]} '
        f'rules={[e["ruleCode"] for e in data["evidences"]]}'
    )


# --------------------------------------------------------------------------
# Hop dong JSON
# --------------------------------------------------------------------------


def test_response_shape_matches_api_spec() -> None:
    data = scan("Tài khoản sắp bị khóa, xác minh tại http://vietc0mbank.com")

    assert set(data) >= {
        "scanId",
        "input",
        "result",
        "analysis",
        "evidences",
        "recommendation",
        "scannedAt",
        "processingTime",
    }
    assert set(data["result"]) == {
        "riskScore",
        "riskLevel",
        "levelColor",
        "confidence",
    }
    assert 0 <= data["result"]["riskScore"] <= 100
    assert data["result"]["levelColor"] in {"GREEN", "YELLOW", "RED"}
    assert data["recommendation"]["action"] in {"ALLOW", "VERIFY", "BLOCK"}
    assert set(data["analysis"]["extractedEntities"]) == {
        "urls",
        "phoneNumbers",
        "bankAccounts",
        "amounts",
        "otpCodes",
    }


def test_every_point_traces_back_to_a_rule() -> None:
    """Yeu cau cot loi: khong co diem nao khong giai thich duoc."""
    data = scan(
        "Bộ Công an thông báo bạn liên quan vụ án, yêu cầu chuyển khoản gấp để xác minh"
    )
    total = sum(e["score"] for e in data["evidences"])
    assert data["result"]["riskScore"] == max(0, min(100, total))
    for ev in data["evidences"]:
        assert ev["ruleCode"] and ev["ruleName"]
        assert ev["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert ev["source"] == "rule"


def test_deterministic() -> None:
    """Cung input phai ra cung diem - dieu ma LLM thuan tuy khong bao dam duoc."""
    text = "Bạn đã trúng thưởng 100 triệu, đóng phí 500k để nhận"
    scores = {scan(text)["result"]["riskScore"] for _ in range(5)}
    assert len(scores) == 1


# --------------------------------------------------------------------------
# Trich xuat thuc the
# --------------------------------------------------------------------------


def test_entity_extraction() -> None:
    data = scan(
        "Chuyển khoản 500k vào STK 19001234567 rồi gọi 0912345678, "
        "chi tiết tại http://vietc0mbank.com"
    )
    ent = data["analysis"]["extractedEntities"]
    assert "+84912345678" in ent["phoneNumbers"]
    assert "19001234567" in ent["bankAccounts"]
    assert any("500k" in a for a in ent["amounts"])
    assert "http://vietc0mbank.com" in ent["urls"]
    # So dien thoai khong duoc dem nham thanh so tai khoan
    assert "0912345678" not in ent["bankAccounts"]


# --------------------------------------------------------------------------
# Validate dau vao
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"text": "", "source": "SMS"},
        {"text": "   ", "source": "SMS"},
        {"text": "a" * 5001, "source": "SMS"},
        {"source": "SMS"},
        {"text": "hello", "source": "TELEGRAM"},
    ],
    ids=["empty", "blank", "too_long", "missing_text", "bad_source"],
)
def test_validation_returns_400(payload: dict) -> None:
    resp = client.post("/v1/scan/text", json=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["success"] is False
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["details"]


# --------------------------------------------------------------------------
# Endpoint phu
# --------------------------------------------------------------------------


def test_health() -> None:
    body = client.get("/health").json()
    assert body["status"] == "UP"
    assert body["ruleCount"] > 0


def test_active_rules_do_not_leak_conditions() -> None:
    rules = client.get("/v1/rules/active").json()
    assert len(rules) > 0
    for r in rules:
        assert set(r) == {"code", "name", "category", "weight", "severity"}
