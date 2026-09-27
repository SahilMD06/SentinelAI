"""Agentic observability: traces, spans, token spend and latency percentiles."""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..models import AgentRun, TraceSpan, User
from ..schemas import SpanOut, TraceSummary, TracingStats
from ..services import tracing as tracing_service

router = APIRouter(prefix="/tracing", tags=["observability"])


@router.get("/stats", response_model=TracingStats, summary="Aggregate telemetry")
def stats(
    hours: int = Query(default=168, ge=1, le=24 * 90),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> TracingStats:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    spans = list(
        db.execute(select(TraceSpan).where(TraceSpan.started_at >= since)).scalars().all()
    )
    durations = sorted(s.duration_ms for s in spans) or [0]

    by_agent: dict[str, dict] = {}
    for span in spans:
        if not span.name.startswith("agent:"):
            continue
        key = span.name.split(":", 1)[1]
        entry = by_agent.setdefault(
            key,
            {"agent": key, "calls": 0, "tokens_in": 0, "tokens_out": 0,
             "cost_usd": 0.0, "durations": [], "errors": 0},
        )
        entry["calls"] += 1
        entry["tokens_in"] += span.tokens_in
        entry["tokens_out"] += span.tokens_out
        entry["cost_usd"] += span.cost_usd
        entry["durations"].append(span.duration_ms)
        if span.status != "ok":
            entry["errors"] += 1

    agents = []
    for entry in by_agent.values():
        durs = sorted(entry.pop("durations")) or [0]
        entry["avg_ms"] = int(statistics.mean(durs))
        entry["p95_ms"] = int(durs[max(int(len(durs) * 0.95) - 1, 0)])
        entry["cost_usd"] = round(entry["cost_usd"], 6)
        agents.append(entry)
    agents.sort(key=lambda e: -e["calls"])

    return TracingStats(
        exporter=tracing_service.exporter_name(),
        project=settings.tracing_project,
        total_traces=len({s.trace_id for s in spans}),
        total_spans=len(spans),
        tokens_in=sum(s.tokens_in for s in spans),
        tokens_out=sum(s.tokens_out for s in spans),
        cost_usd=round(sum(s.cost_usd for s in spans), 6),
        p50_ms=int(durations[len(durations) // 2]),
        p95_ms=int(durations[max(int(len(durations) * 0.95) - 1, 0)]),
        by_agent=agents,
    )


@router.get("/traces", response_model=list[TraceSummary], summary="Recent traces")
def traces(
    limit: int = Query(default=40, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[TraceSummary]:
    rows = db.execute(
        select(
            TraceSpan.trace_id,
            func.min(TraceSpan.started_at).label("started_at"),
            func.count(TraceSpan.id).label("spans"),
            func.sum(TraceSpan.tokens_in),
            func.sum(TraceSpan.tokens_out),
            func.sum(TraceSpan.cost_usd),
            func.max(TraceSpan.duration_ms),
        )
        .group_by(TraceSpan.trace_id)
        .order_by(func.min(TraceSpan.started_at).desc())
        .limit(limit)
    ).all()

    summaries: list[TraceSummary] = []
    for trace_id, started_at, spans, tin, tout, cost, duration in rows:
        root = db.execute(
            select(TraceSpan)
            .where(TraceSpan.trace_id == trace_id, TraceSpan.parent_span_id.is_(None))
            .limit(1)
        ).scalar_one_or_none()
        errored = db.execute(
            select(func.count()).select_from(TraceSpan)
            .where(TraceSpan.trace_id == trace_id, TraceSpan.status != "ok")
        ).scalar_one()
        summaries.append(
            TraceSummary(
                trace_id=trace_id,
                root_name=root.name if root else "unknown",
                started_at=started_at,
                duration_ms=int(duration or 0),
                spans=int(spans),
                tokens_in=int(tin or 0),
                tokens_out=int(tout or 0),
                cost_usd=round(float(cost or 0), 6),
                status="error" if errored else "ok",
            )
        )
    return summaries


@router.get("/traces/{trace_id}", summary="Full span tree for one trace")
def trace_detail(
    trace_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict:
    spans = list(
        db.execute(
            select(TraceSpan).where(TraceSpan.trace_id == trace_id)
            .order_by(TraceSpan.started_at)
        ).scalars().all()
    )
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")

    run = db.execute(
        select(AgentRun).where(AgentRun.trace_id == trace_id)
    ).scalar_one_or_none()

    return {
        "trace_id": trace_id,
        "exporter": spans[0].exporter,
        "spans": [SpanOut.model_validate(s) for s in spans],
        "totals": {
            "spans": len(spans),
            "tokens_in": sum(s.tokens_in for s in spans),
            "tokens_out": sum(s.tokens_out for s in spans),
            "cost_usd": round(sum(s.cost_usd for s in spans), 6),
            "duration_ms": max(s.duration_ms for s in spans),
        },
        "incident": (
            {"id": run.incident_id, "ref": run.incident.ref, "status": run.status,
             "verdict": run.verdict, "risk_score": run.final_risk_score}
            if run else None
        ),
    }


@router.get("/config", summary="Exporter configuration")
def config(_user: User = Depends(get_current_user)) -> dict:
    return {
        **tracing_service.status(),
        "cost_model": {
            "input_per_1k_usd": tracing_service.COST_PER_1K_IN,
            "output_per_1k_usd": tracing_service.COST_PER_1K_OUT,
        },
        "note": (
            "Spans are always written to the SentinelAI trace store. Configuring LangSmith or "
            "Phoenix forwards the same spans to that platform in addition — it does not replace "
            "this panel."
        ),
    }
