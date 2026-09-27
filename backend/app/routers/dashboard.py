"""Command-centre aggregates for the overview screen."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..models import AnomalyAlert, Incident, SecurityEvent, User
from ..schemas import DashboardOut, IncidentSummary, MetricPoint
from ..services import mitre
from ..utils import as_utc, minutes_between

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

CLOSED = ["closed", "false_positive"]


@router.get("", response_model=DashboardOut, summary="Command-centre metrics")
def dashboard(
    hours: int = Query(default=24, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> DashboardOut:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=hours)

    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(Incident.status.notin_(CLOSED))
    ).scalar_one()
    critical = db.execute(
        select(func.count()).select_from(Incident)
        .where(Incident.severity == "critical", Incident.status.notin_(CLOSED))
    ).scalar_one()
    events_window = db.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.ts >= window_start)
    ).scalar_one()
    anomalies_open = db.execute(
        select(func.count()).select_from(AnomalyAlert).where(AnomalyAlert.status == "open")
    ).scalar_one()

    # Mean time to remediate, over cases that actually closed.
    closed = db.execute(
        select(Incident.created_at, Incident.closed_at)
        .where(Incident.closed_at.isnot(None))
        .limit(500)
    ).all()
    durations = [minutes_between(c, cl) for c, cl in closed if cl]
    mttr = int(sum(durations) / len(durations)) if durations else 0

    severity_rows = db.execute(
        select(Incident.severity, func.count())
        .where(Incident.status.notin_(CLOSED))
        .group_by(Incident.severity)
    ).all()
    status_rows = db.execute(
        select(Incident.status, func.count()).group_by(Incident.status)
    ).all()
    source_rows = db.execute(
        select(SecurityEvent.source, func.count())
        .where(SecurityEvent.ts >= window_start)
        .group_by(SecurityEvent.source)
        .order_by(func.count().desc())
        .limit(8)
    ).all()

    # Event volume timeline
    stamps = db.execute(
        select(SecurityEvent.ts).where(SecurityEvent.ts >= window_start)
    ).scalars().all()
    buckets = 24
    width = (hours * 3600) / buckets
    counts = [0] * buckets
    for ts in stamps:
        idx = min(int((as_utc(ts) - window_start).total_seconds() / width), buckets - 1)
        counts[idx] += 1
    timeline = [
        MetricPoint(
            label=(window_start + timedelta(seconds=width * i)).isoformat(),
            value=float(counts[i]),
        )
        for i in range(buckets)
    ]

    # Technique frequency across open cases
    technique_rows = db.execute(
        select(Incident.mitre_techniques).where(Incident.status.notin_(CLOSED))
    ).scalars().all()
    technique_counts: dict[str, int] = {}
    for techniques in technique_rows:
        for tid in techniques or []:
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
    top_techniques = [
        {
            "id": tid,
            "name": (mitre.technique(tid) or {}).get("name", tid),
            "tactic": (mitre.technique(tid) or {}).get("tactic", "—"),
            "count": count,
        }
        for tid, count in sorted(technique_counts.items(), key=lambda kv: -kv[1])[:8]
    ]

    # Detection coverage: techniques seen vs techniques we have guidance for
    covered = len({t for t in technique_counts if mitre.technique(t)})
    coverage = round(covered / max(len(mitre.TECHNIQUES), 1) * 100)

    risk_rows = db.execute(
        select(Incident.risk_score).where(Incident.status.notin_(CLOSED))
    ).scalars().all()
    risk_index = int(sum(risk_rows) / len(risk_rows)) if risk_rows else 0

    recent = db.execute(
        select(Incident).options(selectinload(Incident.assignee))
        .order_by(Incident.created_at.desc()).limit(8)
    ).scalars().all()
    recent_summaries = []
    for r in recent:
        item = IncidentSummary.model_validate(r)
        item.assignee_name = r.assignee.full_name if r.assignee else None
        recent_summaries.append(item)

    latest_ts = db.execute(select(func.max(SecurityEvent.ts))).scalar_one()
    lag = 0.0
    if latest_ts is not None:
        lag = max((now - as_utc(latest_ts)).total_seconds(), 0.0)

    return DashboardOut(
        open_incidents=open_incidents,
        critical_incidents=critical,
        events_24h=events_window,
        anomalies_open=anomalies_open,
        mttr_minutes=mttr,
        detection_coverage=coverage,
        risk_index=risk_index,
        severity_breakdown=[MetricPoint(label=s, value=float(c)) for s, c in severity_rows],
        status_breakdown=[MetricPoint(label=s, value=float(c)) for s, c in status_rows],
        events_timeline=timeline,
        top_sources=[MetricPoint(label=s, value=float(c)) for s, c in source_rows],
        top_techniques=top_techniques,
        pipeline={
            "ingest_rate_per_min": round(events_window / max(hours * 60, 1), 2),
            "lag_seconds": round(lag, 1),
            "status": "healthy" if lag < 900 else "degraded",
            "window_hours": hours,
        },
        recent_incidents=recent_summaries,
    )


@router.get("/sla", summary="SLA breach watchlist")
def sla_watch(
    db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict:
    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(Incident).options(selectinload(Incident.assignee))
        .where(Incident.status.notin_(CLOSED), Incident.sla_due_at.isnot(None))
        .order_by(Incident.sla_due_at)
        .limit(40)
    ).scalars().all()

    breached, at_risk = [], []
    for incident in rows:
        due = as_utc(incident.sla_due_at)
        remaining = int((due - now).total_seconds() / 60)
        entry = {
            "ref": incident.ref, "title": incident.title, "severity": incident.severity,
            "risk_score": incident.risk_score, "status": incident.status,
            "due_at": due, "minutes_remaining": remaining,
            "assignee": incident.assignee.full_name if incident.assignee else None,
        }
        (breached if remaining < 0 else at_risk).append(entry)

    return {
        "breached": breached,
        "at_risk": [e for e in at_risk if e["minutes_remaining"] <= 240],
        "upcoming": [e for e in at_risk if e["minutes_remaining"] > 240][:10],
        "generated_at": now,
    }
