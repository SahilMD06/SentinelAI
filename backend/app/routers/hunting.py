"""Threat-hunting console: Lucene-style search over raw log text."""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import SavedHunt, SecurityEvent, User
from ..schemas import EventOut, HuntFacet, HuntRequest, HuntResponse, SavedHuntIn, SavedHuntOut
from ..services.log_parser import FIELD_MAP, QUERY_EXAMPLES, apply_query, parse_query
from ..utils import as_utc

router = APIRouter(prefix="/hunt", tags=["hunting"])


@router.post("/search", response_model=HuntResponse, summary="Execute a hunting query")
def search(
    payload: HuntRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> HuntResponse:
    started = time.perf_counter()
    parsed = parse_query(payload.query)

    stmt = select(SecurityEvent)
    stmt = apply_query(stmt, SecurityEvent, parsed)
    if payload.start:
        stmt = stmt.where(SecurityEvent.ts >= payload.start)
    if payload.end:
        stmt = stmt.where(SecurityEvent.ts <= payload.end)

    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(
        db.execute(stmt.order_by(SecurityEvent.ts.desc()).limit(payload.limit)).scalars().all()
    )

    facets = [
        HuntFacet(field=field, values=[
            {"value": value, "count": count}
            for value, count in Counter(
                getattr(r, field) for r in rows if getattr(r, field) is not None
            ).most_common(8)
        ])
        for field in ("severity", "source", "event_type", "host", "src_ip")
    ]

    histogram: list[dict] = []
    if rows:
        stamps = [as_utc(r.ts) for r in rows]
        newest, oldest = max(stamps), min(stamps)
        span = max((newest - oldest).total_seconds(), 60)
        buckets = 24
        width = span / buckets
        counts = [0] * buckets
        for ts in stamps:
            idx = min(int((ts - oldest).total_seconds() / width), buckets - 1)
            counts[idx] += 1
        histogram = [
            {
                "bucket": (oldest + timedelta(seconds=width * i)).isoformat(),
                "count": counts[i],
            }
            for i in range(buckets)
        ]

    return HuntResponse(
        items=[EventOut.model_validate(r) for r in rows],
        total=total,
        took_ms=int((time.perf_counter() - started) * 1000),
        parsed_filters=parsed.as_dict(),
        facets=facets,
        histogram=histogram,
        warnings=parsed.warnings,
    )


@router.get("/schema", summary="Searchable fields, operators and examples")
def schema(_user: User = Depends(get_current_user)) -> dict:
    return {
        "fields": sorted(set(FIELD_MAP)),
        "field_map": FIELD_MAP,
        "operators": [
            {"op": ":", "meaning": "equals (wildcards with *)"},
            {"op": ">=", "meaning": "numeric greater-or-equal"},
            {"op": "<=", "meaning": "numeric less-or-equal"},
            {"op": ">", "meaning": "numeric greater than"},
            {"op": "<", "meaning": "numeric less than"},
            {"op": "-", "meaning": "negate the following term"},
            {"op": "NOT", "meaning": "negate the following term"},
            {"op": '"…"', "meaning": "exact phrase over message and raw text"},
        ],
        "examples": [{"query": q, "description": d} for q, d in QUERY_EXAMPLES],
    }


@router.get("/saved", response_model=list[SavedHuntOut], summary="Saved hunts")
def list_saved(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[SavedHunt]:
    stmt = select(SavedHunt).where(
        (SavedHunt.shared.is_(True)) | (SavedHunt.owner_id == user.id)
    ).order_by(SavedHunt.created_at.desc())
    return list(db.execute(stmt).scalars().all())


@router.post("/saved", response_model=SavedHuntOut, status_code=201, summary="Save a hunt")
def save_hunt(
    payload: SavedHuntIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("hunt:save")),
) -> SavedHunt:
    hunt = SavedHunt(name=payload.name.strip(), query=payload.query.strip(),
                     owner_id=user.id, shared=True)
    db.add(hunt)
    record_audit(db, actor=user, action="hunt.save", target_type="hunt",
                 target_id=payload.name, request=request)
    db.commit()
    db.refresh(hunt)
    return hunt


@router.delete("/saved/{hunt_id}", summary="Delete a saved hunt")
def delete_hunt(
    hunt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("hunt:save")),
) -> dict:
    hunt = db.get(SavedHunt, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    if hunt.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the owner or an admin can delete this hunt.")
    db.delete(hunt)
    db.commit()
    return {"detail": f"Deleted saved hunt {hunt_id}"}


@router.get("/timeline", summary="Event volume over time for the hunt histogram")
def timeline(
    hours: int = Query(default=24, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.ts, SecurityEvent.severity).where(SecurityEvent.ts >= start)
    ).all()

    buckets = 24
    width = (hours * 3600) / buckets
    series: dict[str, list[int]] = {}
    for ts, severity in rows:
        ts = as_utc(ts)
        idx = min(int((ts - start).total_seconds() / width), buckets - 1)
        series.setdefault(severity, [0] * buckets)[idx] += 1

    return {
        "start": start,
        "end": now,
        "bucket_seconds": int(width),
        "buckets": [
            (start + timedelta(seconds=width * i)).isoformat() for i in range(buckets)
        ],
        "series": [{"severity": k, "counts": v} for k, v in series.items()],
        "total": len(rows),
    }
