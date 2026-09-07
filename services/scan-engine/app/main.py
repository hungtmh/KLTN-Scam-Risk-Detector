"""Scan Engine - API server cua Anti-Scam Platform (moc M1).

Chay:  uvicorn app.main:app --reload --port 8000
Docs:  http://127.0.0.1:8000/docs
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
from .engine.rules import get_ruleset

app = FastAPI(
    title="Anti-Scam Scan Engine",
    description=(
        "Rule engine giai thich duoc cho noi dung tin nhan tieng Viet. "
        "Moi diem rui ro deu tra ve kem ruleCode de truy nguoc."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # M1 chay local; siet lai khi deploy
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Doi 422 mac dinh cua FastAPI thanh 400 theo dinh dang loi cua du an."""
    details = [
        {
            "field": ".".join(str(p) for p in err["loc"][1:]) or "body",
            "message": err["msg"],
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Du lieu gui len khong hop le",
                "details": details,
            },
        },
    )


@app.get("/health", tags=["ops"], summary="Kiem tra service song va bo rule da nap")
def health() -> dict:
    rs = get_ruleset()
    return {
        "status": "UP",
        "rulesVersion": rs.version,
        "ruleCount": len(rs.rules) + len(rs.keyword_groups),
    }
