"""ML anomaly-detection surface: alerts, model status and manual retraining."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import AnomalyAlert, ModelSnapshot, SecurityEvent, User
from ..schemas import AnomalyOut, ModelSnapshotOut
from ..services import anomaly as anomaly_service

router = APIRouter(prefix="/anomalies", tags=["anomaly-detection"])


@router.get("", response_model=list[AnomalyOut], summary="Anomaly alerts")
def list_alerts(
    status: str | None = Query(default=None, pattern="^(open|triaged|dismissed)$"),
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[AnomalyAlert]:
    stmt = select(AnomalyAlert).order_by(AnomalyAlert.score.desc()).limit(limit)
    if status:
        stmt = stmt.where(AnomalyAlert.status == status)
    if severity:
        stmt = stmt.where(AnomalyAlert.severity == severity)
    return list(db.execute(stmt).scalars().all())


@router.get("/status", summary="Detector status and feature schema")
def status(_user: User = Depends(get_current_user)) -> dict:
    return anomaly_service.status()


@router.get("/model-history", response_model=list[ModelSnapshotOut], summary="Training history")
def model_history(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[ModelSnapshot]:
    return list(
        db.execute(
            select(ModelSnapshot).order_by(ModelSnapshot.trained_at.desc()).limit(limit)
        ).scalars().all()
    )


@router.post("/retrain", summary="Retrain the detector now")
def retrain(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("anomaly:write")),
) -> dict:
    record_audit(db, actor=user, action="anomaly.retrain", target_type="model",
                 target_id="anomaly-detector", request=request)
    db.commit()
    background.add_task(_retrain_and_score)
    return {
        "detail": "Retraining scheduled. The detector fits on nominal traffic, then rescores "
                  "the last 48 hours.",
        "status": anomaly_service.status(),
    }


def _retrain_and_score() -> None:
    anomaly_service.train(force=True)
    anomaly_service.score_recent()


@router.patch("/{alert_id}", response_model=AnomalyOut, summary="Triage an alert")
def update_alert(
    alert_id: int,
    request: Request,
    new_status: str = Query(alias="status", pattern="^(open|triaged|dismissed)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("anomaly:write")),
) -> AnomalyAlert:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Anomaly alert not found")
    alert.status = new_status
    record_audit(db, actor=user, action="anomaly.triage", target_type="anomaly",
                 target_id=alert_id, detail=f"status={new_status}", request=request)
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/{alert_id}/context", summary="Alert with its originating event")
def alert_context(
    alert_id: int, db: Session = Depends(get_db), _user: User = Depends(get_current_user)
) -> dict:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Anomaly alert not found")
    event = db.get(SecurityEvent, alert.event_id) if alert.event_id else None
    return {
        "alert": AnomalyOut.model_validate(alert),
        "event": (
            {
                "id": event.id, "ts": event.ts, "host": event.host, "source": event.source,
                "src_ip": event.src_ip, "username": event.username,
                "event_type": event.event_type, "severity": event.severity,
                "message": event.message, "raw": event.raw,
                "bytes_out": event.bytes_out, "dest_port": event.dest_port,
            }
            if event else None
        ),
        "feature_schema": anomaly_service.FEATURE_NAMES,
    }
