"""Threat-intel reputation lookups with cache introspection."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import IntelRecord, User
from ..schemas import IntelOut, IntelRequest
from ..services import threat_intel
from ..services.cache import cache_status

router = APIRouter(prefix="/intel", tags=["threat-intel"])


@router.get("/status", summary="Provider and cache configuration")
def status(_user: User = Depends(get_current_user)) -> dict:
    return {"intel": threat_intel.status(), "cache": cache_status()}


@router.post("/lookup", response_model=IntelOut, summary="Reputation lookup")
def lookup(
    payload: IntelRequest,
    request: Request,
    refresh: bool = Query(default=False, description="Bypass the 24h cache"),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("intel:lookup")),
) -> IntelOut:
    result = threat_intel.lookup(payload.indicator, force_refresh=refresh)
    record_audit(db, actor=user, action="intel.lookup", target_type="indicator",
                 target_id=payload.indicator,
                 detail=f"verdict={result['verdict']} live={result['live']}", request=request)
    db.commit()
    return IntelOut(**result)


@router.get("/history", summary="Previously resolved indicators")
def history(
    limit: int = Query(default=50, ge=1, le=300),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    rows = db.execute(
        select(IntelRecord).order_by(IntelRecord.fetched_at.desc()).limit(limit)
    ).scalars().all()
    now = datetime.now(timezone.utc)
    return {
        "items": [
            {
                "indicator": r.indicator,
                "indicator_type": r.indicator_type,
                "provider": r.provider,
                "verdict": r.verdict,
                "score": r.score,
                "live": r.live,
                "fetched_at": r.fetched_at,
                "expires_at": r.expires_at,
                "expired": bool(
                    r.expires_at
                    and (r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)) < now
                ),
            }
            for r in rows
        ],
        "count": len(rows),
    }
