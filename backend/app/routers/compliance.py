"""ISO 27001 / SOC 2 posture, gap register and PDF evidence export."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import ComplianceControl, Incident, User
from ..schemas import ComplianceOverview, ControlOut, ControlUpdate, FrameworkScore
from ..services import pdf_export

router = APIRouter(prefix="/compliance", tags=["compliance"])

STATUS_SCORE = {"compliant": 100, "partial": 55, "gap": 0}

FRAMEWORK_META = {
    "ISO27001": {
        "label": "ISO/IEC 27001:2022",
        "description": (
            "International standard for information security management systems. "
            "Annex A defines 93 controls across organisational, people, physical and "
            "technological themes."
        ),
        "certification": "Stage 2 audit scheduled",
    },
    "SOC2": {
        "label": "SOC 2 Type II",
        "description": (
            "AICPA Trust Services Criteria covering security, availability, processing "
            "integrity, confidentiality and privacy over an observation window."
        ),
        "certification": "Observation window in progress",
    },
}


def _score(controls: list[ComplianceControl], framework: str) -> FrameworkScore:
    scoped = [c for c in controls if c.framework == framework]
    scoring = [c for c in scoped if c.status != "na"]
    mean = round(sum(STATUS_SCORE.get(c.status, 0) for c in scoring) / len(scoring)) if scoring else 0
    return FrameworkScore(
        framework=framework,
        score=mean,
        compliant=sum(1 for c in scoped if c.status == "compliant"),
        partial=sum(1 for c in scoped if c.status == "partial"),
        gaps=sum(1 for c in scoped if c.status == "gap"),
        not_applicable=sum(1 for c in scoped if c.status == "na"),
        total=len(scoped),
    )


@router.get("/overview", response_model=ComplianceOverview, summary="Framework scorecards")
def overview(
    db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> ComplianceOverview:
    controls = list(db.execute(select(ComplianceControl)).scalars().all())
    frameworks = sorted({c.framework for c in controls})
    gaps = [c for c in controls if c.status == "gap"]
    return ComplianceOverview(
        frameworks=[_score(controls, f) for f in frameworks],
        open_gaps=[ControlOut.model_validate(c) for c in
                   sorted(gaps, key=lambda c: (c.framework, c.control_id))],
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/frameworks", summary="Framework metadata")
def frameworks(_user: User = Depends(get_current_user)) -> dict:
    return {"frameworks": [{"key": k, **v} for k, v in FRAMEWORK_META.items()]}


@router.get("/controls", response_model=list[ControlOut], summary="Control register")
def controls(
    framework: str | None = None,
    status: str | None = None,
    q: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[ComplianceControl]:
    stmt = select(ComplianceControl).order_by(
        ComplianceControl.framework, ComplianceControl.control_id
    )
    if framework:
        stmt = stmt.where(ComplianceControl.framework == framework)
    if status:
        stmt = stmt.where(ComplianceControl.status == status)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            ComplianceControl.title.ilike(like) | ComplianceControl.control_id.ilike(like)
        )
    return list(db.execute(stmt).scalars().all())


@router.patch("/controls/{control_id}", response_model=ControlOut, summary="Update a control")
def update_control(
    control_id: int,
    payload: ControlUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("compliance:write")),
) -> ComplianceControl:
    control = db.get(ComplianceControl, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Control not found")

    if payload.status:
        control.status = payload.status
        control.score = STATUS_SCORE.get(payload.status, control.score)
    if payload.evidence is not None:
        control.evidence = payload.evidence
    if payload.gap_notes is not None:
        control.gap_notes = payload.gap_notes
    if payload.owner:
        control.owner = payload.owner
    control.last_reviewed = datetime.now(timezone.utc)

    record_audit(db, actor=user, action="compliance.control.update", target_type="control",
                 target_id=f"{control.framework}:{control.control_id}", request=request)
    db.commit()
    db.refresh(control)
    return control


@router.get("/incident-linkage", summary="Controls implicated by open incidents")
def incident_linkage(
    db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict:
    from ..services.agent_pipeline import CONTROL_IMPACT, DEFAULT_CONTROLS

    incidents = db.execute(
        select(Incident).where(Incident.status.notin_(["closed", "false_positive"]))
    ).scalars().all()

    linkage: dict[str, dict] = {}
    for incident in incidents:
        for framework, cid, title, note in CONTROL_IMPACT.get(incident.category, []) + DEFAULT_CONTROLS:
            key = f"{framework}:{cid}"
            entry = linkage.setdefault(
                key,
                {"framework": framework, "control_id": cid, "title": title,
                 "note": note, "incidents": []},
            )
            entry["incidents"].append(
                {"ref": incident.ref, "severity": incident.severity,
                 "risk_score": incident.risk_score, "title": incident.title}
            )

    ranked = sorted(linkage.values(), key=lambda e: -len(e["incidents"]))
    return {
        "open_incidents": len(incidents),
        "controls_under_pressure": ranked[:20],
        "generated_at": datetime.now(timezone.utc),
    }


@router.get("/report.pdf", summary="Download the compliance report as PDF")
def compliance_pdf(
    request: Request,
    framework: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("reports:export")),
) -> Response:
    stmt = select(ComplianceControl)
    if framework:
        stmt = stmt.where(ComplianceControl.framework == framework)
    controls_list = list(db.execute(stmt).scalars().all())
    if not controls_list:
        raise HTTPException(status_code=404, detail="No controls in scope for this framework")

    all_controls = list(db.execute(select(ComplianceControl)).scalars().all())
    scores = [
        _score(all_controls, f).model_dump()
        for f in ([framework] if framework else sorted({c.framework for c in all_controls}))
    ]
    pdf = pdf_export.compliance_report(
        controls_list, scores, generated_by=user.full_name,
        framework=FRAMEWORK_META.get(framework or "", {}).get("label", framework),
    )
    record_audit(db, actor=user, action="report.compliance.export", target_type="compliance",
                 target_id=framework or "all", request=request)
    db.commit()
    name = f"sentinelai-compliance-{(framework or 'all').lower()}.pdf"
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
