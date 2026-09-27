"""Incident queue, case detail, playbooks, notes, agent runs and simulation."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import (
    AgentRun,
    Incident,
    IncidentNote,
    IncidentStatus,
    PlaybookItem,
    SecurityEvent,
    Severity,
    User,
)
from ..schemas import (
    AgentRunOut,
    EventOut,
    IncidentDetail,
    IncidentPage,
    IncidentSummary,
    IncidentUpdate,
    NoteCreate,
    NoteOut,
    PlaybookItemOut,
    PlaybookToggle,
    SimulationRequest,
    ThreatChain,
)
from ..services import mitre, pdf_export, playbooks
from ..services.agent_pipeline import AGENT_CATALOG, build_threat_chain, run_pipeline
from ..utils import as_utc

router = APIRouter(prefix="/incidents", tags=["incidents"])

SORTABLE = {
    "created_at": Incident.created_at,
    "risk_score": Incident.risk_score,
    "updated_at": Incident.updated_at,
    "severity": Incident.severity,
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _summary(inc: Incident, task_counts: dict[int, tuple[int, int]] | None = None) -> IncidentSummary:
    done, total = (task_counts or {}).get(inc.id, (0, 0))
    payload = IncidentSummary.model_validate(inc)
    payload.assignee_name = inc.assignee.full_name if inc.assignee else None
    payload.total_tasks = total
    payload.open_tasks = total - done
    return payload


def _task_counts(db: Session, incident_ids: list[int]) -> dict[int, tuple[int, int]]:
    if not incident_ids:
        return {}
    rows = db.execute(
        select(
            PlaybookItem.incident_id,
            func.sum(case((PlaybookItem.completed.is_(True), 1), else_=0)),
            func.count(PlaybookItem.id),
        )
        .where(PlaybookItem.incident_id.in_(incident_ids))
        .group_by(PlaybookItem.incident_id)
    ).all()
    return {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in rows}


@router.get("", response_model=IncidentPage, summary="Incident queue")
def list_incidents(
    q: str | None = Query(default=None, description="Free text over ref, title, asset, source IP"),
    severity: list[str] | None = Query(default=None),
    status_filter: list[str] | None = Query(default=None, alias="status"),
    category: str | None = None,
    assignee_id: int | None = None,
    unassigned: bool = False,
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> IncidentPage:
    stmt = select(Incident).options(selectinload(Incident.assignee))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Incident.ref.ilike(like), Incident.title.ilike(like),
                Incident.asset.ilike(like), Incident.src_ip.ilike(like),
                Incident.summary.ilike(like),
            )
        )
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))
    if status_filter:
        stmt = stmt.where(Incident.status.in_(status_filter))
    if category:
        stmt = stmt.where(Incident.category == category)
    if assignee_id:
        stmt = stmt.where(Incident.assignee_id == assignee_id)
    if unassigned:
        stmt = stmt.where(Incident.assignee_id.is_(None))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    column = SORTABLE.get(sort, Incident.created_at)
    stmt = stmt.order_by(column.desc() if order == "desc" else column.asc())
    stmt = stmt.offset((page - 1) * size).limit(size)
    rows = list(db.execute(stmt).scalars().all())
    counts = _task_counts(db, [r.id for r in rows])

    return IncidentPage(
        items=[_summary(r, counts) for r in rows], total=total, page=page, size=size,
    )


@router.get("/facets", summary="Queue filter facets")
def facets(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> dict:
    def group(column):
        return [
            {"value": v, "count": c}
            for v, c in db.execute(
                select(column, func.count()).group_by(column).order_by(func.count().desc())
            ).all()
        ]

    return {
        "severity": group(Incident.severity),
        "status": group(Incident.status),
        "category": group(Incident.category),
        "detection_source": group(Incident.detection_source),
        "statuses": [s.value for s in IncidentStatus],
        "severities": SEVERITY_ORDER,
        "agents": AGENT_CATALOG,
    }


@router.get("/{ref}", response_model=IncidentDetail, summary="Case detail")
def get_incident(
    ref: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> IncidentDetail:
    incident = _load(db, ref)
    counts = _task_counts(db, [incident.id])
    detail = IncidentDetail.model_validate(incident)
    detail.assignee_name = incident.assignee.full_name if incident.assignee else None
    done, total = counts.get(incident.id, (0, 0))
    detail.total_tasks, detail.open_tasks = total, total - done

    detail.notes = [
        NoteOut(
            id=n.id, body=n.body, kind=n.kind, created_at=n.created_at,
            author_name=n.author.full_name if n.author else "System",
        )
        for n in sorted(incident.notes, key=lambda n: as_utc(n.created_at) or datetime.min.replace(tzinfo=timezone.utc))
    ]
    detail.playbook_items = [
        PlaybookItemOut(
            id=i.id, position=i.position, phase=i.phase, title=i.title, detail=i.detail,
            completed=i.completed, completed_at=i.completed_at, automatable=i.automatable,
            completed_by=_user_name(db, i.completed_by_id),
        )
        for i in sorted(incident.playbook_items, key=lambda i: i.position)
    ]
    detail.runs = [AgentRunOut.model_validate(r) for r in
                   sorted(incident.runs, key=lambda r: as_utc(r.started_at) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)]

    events = db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.incident_id == incident.id)
        .order_by(SecurityEvent.ts)
        .limit(200)
    ).scalars().all()
    detail.events = [EventOut.model_validate(e) for e in events]
    detail.threat_chain = ThreatChain.model_validate(build_threat_chain(incident, list(events)))
    return detail


def _user_name(db: Session, user_id: int | None) -> str | None:
    if not user_id:
        return None
    user = db.get(User, user_id)
    return user.full_name if user else None


def _load(db: Session, ref: str) -> Incident:
    stmt = select(Incident).options(
        selectinload(Incident.assignee),
        selectinload(Incident.notes).selectinload(IncidentNote.author),
        selectinload(Incident.playbook_items),
        selectinload(Incident.runs).selectinload(AgentRun.steps),
    )
    stmt = stmt.where(Incident.ref == ref) if not ref.isdigit() else stmt.where(Incident.id == int(ref))
    incident = db.execute(stmt).scalars().unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {ref} not found")
    return incident


@router.patch("/{ref}", response_model=IncidentSummary, summary="Update case fields")
def update_incident(
    ref: str,
    payload: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("incidents:write")),
) -> IncidentSummary:
    incident = _load(db, ref)
    changes: list[str] = []

    if payload.status and payload.status != incident.status:
        if payload.status in {IncidentStatus.CLOSED.value, IncidentStatus.FALSE_POSITIVE.value}:
            if "incidents:close" not in _caps(user):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Closing a case requires SOC Manager or Administrator.",
                )
            incident.closed_at = datetime.now(timezone.utc)
        changes.append(f"status {incident.status}→{payload.status}")
        incident.status = payload.status

    if payload.severity and payload.severity != incident.severity:
        changes.append(f"severity {incident.severity}→{payload.severity}")
        incident.severity = payload.severity
    if payload.priority:
        incident.priority = payload.priority
    if payload.tags is not None:
        incident.tags = payload.tags
    if payload.assignee_id is not None:
        if "incidents:assign" not in _caps(user):
            raise HTTPException(status_code=403, detail="Reassignment requires SOC Manager or Administrator.")
        assignee = db.get(User, payload.assignee_id)
        if assignee is None:
            raise HTTPException(status_code=404, detail="Assignee not found")
        incident.assignee_id = assignee.id
        changes.append(f"assigned to {assignee.full_name}")

    incident.updated_at = datetime.now(timezone.utc)
    if changes:
        db.add(IncidentNote(
            incident_id=incident.id, author_id=user.id, kind="status",
            body=f"Case updated by {user.full_name}: " + "; ".join(changes),
        ))
    record_audit(db, actor=user, action="incident.update", target_type="incident",
                 target_id=incident.ref, detail="; ".join(changes), request=request)
    db.commit()
    db.refresh(incident)
    return _summary(incident, _task_counts(db, [incident.id]))


def _caps(user: User) -> list[str]:
    from ..deps import capabilities_for

    return capabilities_for(user.role)


@router.post("/{ref}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED,
             summary="Add an analyst note")
def add_note(
    ref: str,
    payload: NoteCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("incidents:write")),
) -> NoteOut:
    incident = _load(db, ref)
    note = IncidentNote(
        incident_id=incident.id, author_id=user.id, body=payload.body.strip(), kind="note"
    )
    db.add(note)
    incident.updated_at = datetime.now(timezone.utc)
    record_audit(db, actor=user, action="incident.note", target_type="incident",
                 target_id=incident.ref, request=request)
    db.commit()
    db.refresh(note)
    return NoteOut(id=note.id, body=note.body, kind=note.kind,
                   created_at=note.created_at, author_name=user.full_name)


@router.patch("/{ref}/playbook/{item_id}", response_model=IncidentDetail,
              summary="Toggle a playbook step")
def toggle_playbook_item(
    ref: str,
    item_id: int,
    payload: PlaybookToggle,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("incidents:write")),
) -> IncidentDetail:
    incident = _load(db, ref)
    item = db.get(PlaybookItem, item_id)
    if item is None or item.incident_id != incident.id:
        raise HTTPException(status_code=404, detail="Playbook step not found on this case")

    item.completed = payload.completed
    item.completed_by_id = user.id if payload.completed else None
    item.completed_at = datetime.now(timezone.utc) if payload.completed else None

    items = sorted(incident.playbook_items, key=lambda i: i.position)
    done = sum(1 for i in items if i.completed)
    total = len(items) or 1
    ratio = done / total

    # Checklist progress drives case status — this is the mechanism that makes the
    # playbook a workflow rather than a decorative to-do list.
    previous = incident.status
    if incident.status not in {IncidentStatus.CLOSED.value, IncidentStatus.FALSE_POSITIVE.value}:
        containment_done = all(i.completed for i in items if i.phase == "containment")
        eradication_done = all(i.completed for i in items if i.phase == "eradication")
        recovery_done = all(i.completed for i in items if i.phase == "recovery")
        if ratio >= 1.0:
            incident.status = IncidentStatus.REMEDIATED.value
        elif recovery_done and eradication_done:
            incident.status = IncidentStatus.REMEDIATED.value
        elif eradication_done and containment_done:
            incident.status = IncidentStatus.CONTAINED.value
        elif containment_done and done:
            incident.status = IncidentStatus.CONTAINED.value
        elif done:
            incident.status = IncidentStatus.INVESTIGATING.value
        else:
            incident.status = IncidentStatus.TRIAGING.value

    body = (
        f"{user.full_name} marked step {item.position + 1} "
        f"'{item.title}' as {'complete' if payload.completed else 'incomplete'}. "
        f"Playbook progress {done}/{len(items)}."
    )
    if previous != incident.status:
        body += f" Case status advanced {previous} → {incident.status}."
    db.add(IncidentNote(incident_id=incident.id, author_id=user.id, kind="system", body=body))
    incident.updated_at = datetime.now(timezone.utc)
    record_audit(db, actor=user, action="incident.playbook.toggle", target_type="incident",
                 target_id=incident.ref, detail=body, request=request)
    db.commit()
    return get_incident(incident.ref, db, user)


@router.post("/{ref}/investigate", response_model=AgentRunOut,
             summary="Run the 9-agent investigation pipeline")
def investigate(
    ref: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("agents:run")),
) -> AgentRunOut:
    incident = _load(db, ref)
    run = run_pipeline(db, incident, triggered_by=user, reason=f"manual:{user.email}")
    record_audit(db, actor=user, action="agents.run", target_type="incident",
                 target_id=incident.ref, detail=f"trace={run.trace_id}", request=request)
    db.commit()
    db.refresh(run)
    return AgentRunOut.model_validate(run)


@router.get("/{ref}/threat-chain", summary="Threat-chain graph for the case")
def threat_chain(
    ref: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict:
    incident = _load(db, ref)
    events = db.execute(
        select(SecurityEvent).where(SecurityEvent.incident_id == incident.id).limit(200)
    ).scalars().all()
    return build_threat_chain(incident, list(events))


@router.get("/{ref}/report.pdf", summary="Download the incident report as PDF")
def incident_pdf(
    ref: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("reports:export")),
) -> Response:
    incident = _load(db, ref)
    # Ensure relationships used by the renderer are loaded.
    _ = incident.events, incident.notes, incident.playbook_items, incident.runs
    pdf = pdf_export.incident_report(incident, generated_by=user.full_name)
    record_audit(db, actor=user, action="report.incident.export", target_type="incident",
                 target_id=incident.ref, request=request)
    db.commit()
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{incident.ref}-report.pdf"'},
    )


# ---------------------------------------------------------------------------
# Threat simulation (admin only)
# ---------------------------------------------------------------------------
SCENARIOS = {
    "bruteforce-ssh": {
        "category": "brute-force", "asset": "bastion-01", "criticality": "critical",
        "title": "Simulated SSH brute force against bastion-01",
        "source": "sshd", "events": 26, "detection": "signature",
        "summary": "Simulation: sustained SSH credential guessing from a bulletproof-hosting range.",
    },
    "credential-stuffing": {
        "category": "credential-access", "asset": "app-prod-01", "criticality": "high",
        "title": "Simulated credential stuffing against the customer portal",
        "source": "winauth", "events": 30, "detection": "correlation",
        "summary": "Simulation: breach-corpus credential pairs replayed against the portal.",
    },
    "web-shell": {
        "category": "web-exploit", "asset": "web-edge-01", "criticality": "critical",
        "title": "Simulated web shell deployment on web-edge-01",
        "source": "nginx", "events": 18, "detection": "file-integrity",
        "summary": "Simulation: exploitation followed by a planted script in the web root.",
    },
    "data-exfiltration": {
        "category": "data-exfiltration", "asset": "db-prod-01", "criticality": "critical",
        "title": "Simulated bulk egress from db-prod-01",
        "source": "firewall", "events": 14, "detection": "dlp",
        "summary": "Simulation: large outbound transfer to an unsanctioned destination.",
    },
    "ransomware-precursor": {
        "category": "ransomware", "asset": "file-share-01", "criticality": "critical",
        "title": "Simulated ransomware staging on file-share-01",
        "source": "winauth", "events": 22, "detection": "edr",
        "summary": "Simulation: shadow-copy deletion followed by mass file renames.",
    },
    "privilege-escalation": {
        "category": "privilege-escalation", "asset": "app-prod-02", "criticality": "high",
        "title": "Simulated privilege escalation on app-prod-02",
        "source": "sshd", "events": 12, "detection": "audit",
        "summary": "Simulation: service account obtains root outside the elevation matrix.",
    },
    "dns-tunnelling": {
        "category": "data-exfiltration", "asset": "k8s-node-07", "criticality": "medium",
        "title": "Simulated DNS tunnelling from k8s-node-07",
        "source": "firewall", "events": 20, "detection": "telemetry",
        "summary": "Simulation: high-entropy subdomain queries carrying encoded payload data.",
    },
}


@router.post("/simulate", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED,
             summary="Generate a synthetic incident (admin only)")
def simulate(
    payload: SimulationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("simulate:run")),
) -> IncidentDetail:
    from ..seed import GENERATORS, HOSTILE_IPS, _generator_for

    rng = random.Random()
    key = payload.scenario
    if key == "random":
        key = rng.choice(list(SCENARIOS))
    scenario = SCENARIOS.get(key)
    if scenario is None:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{key}'")

    now = datetime.now(timezone.utc)
    src_ip = rng.choice(HOSTILE_IPS)
    seq = db.execute(select(func.count()).select_from(Incident)).scalar_one() + 1001

    incident = Incident(
        ref=f"SIM-{now:%Y}-{seq}",
        title=scenario["title"],
        summary=f"{scenario['summary']} Injected by {user.full_name} at {now:%H:%M} UTC.",
        severity=Severity.MEDIUM.value, status=IncidentStatus.NEW.value, priority="P3",
        risk_score=0, category=scenario["category"], detection_source=scenario["detection"],
        asset=scenario["asset"], asset_criticality=scenario["criticality"],
        src_ip=src_ip, dest_ip="10.20.10.24", affected_user="svc_deploy",
        mitre_techniques=mitre.CATEGORY_TECHNIQUES.get(scenario["category"], [])[:3],
        tags=["simulation", scenario["category"]],
        created_at=now - timedelta(minutes=scenario["events"]),
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    generator = _generator_for(scenario["source"] if scenario["source"] in GENERATORS else "firewall")
    for i in range(scenario["events"]):
        ts = incident.created_at + timedelta(seconds=i * rng.randrange(3, 30))
        event = generator(rng, ts, scenario["asset"], src_ip, hostile=True)
        event["incident_id"] = incident.id
        db.add(SecurityEvent(**event))

    key_pb, pb = playbooks.for_category(scenario["category"])
    incident.playbook_key = key_pb
    db.flush()

    record_audit(db, actor=user, action="simulate.run", target_type="incident",
                 target_id=incident.ref, detail=f"scenario={key}", request=request)

    if payload.run_agents:
        run_pipeline(db, incident, triggered_by=user, reason=f"simulation:{key}")

    db.commit()
    return get_incident(incident.ref, db, user)


@router.get("/simulate/scenarios", summary="Available simulation scenarios")
def scenarios(_user: User = Depends(get_current_user)) -> dict:
    return {
        "scenarios": [
            {"key": k, "title": v["title"], "category": v["category"],
             "asset": v["asset"], "events": v["events"]}
            for k, v in SCENARIOS.items()
        ]
    }
