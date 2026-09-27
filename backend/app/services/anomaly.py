"""Unsupervised anomaly detection daemon.

An Isolation Forest is trained on historical *nominal* telemetry (events with
no signature match and no critical severity — the closest available proxy for
"normal"), then scores recent traffic. Statistical outliers become Anomaly
Alerts that sit alongside signature detections in the SOC feed.

Feature vector, per event:
  0  hour of day (cyclic → sin)      4  bytes_out (log1p)
  1  hour of day (cyclic → cos)      5  bytes_in  (log1p)
  2  day of week                     6  destination port (log1p)
  3  is_off_hours (22:00–06:00)      7  severity ordinal
  8  status_code bucket              9  events from same src in the hour
 10  distinct users touched by src   11  message length (log1p)

The cyclic encoding matters: without it, 23:00 and 00:00 look maximally far
apart and every midnight event scores as anomalous.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import select

from ..config import settings
from ..database import session_scope
from ..models import AnomalyAlert, ModelSnapshot, SecurityEvent, Severity
from ..utils import as_utc

log = logging.getLogger("sentinelai.anomaly")

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "day_of_week", "off_hours",
    "log_bytes_out", "log_bytes_in", "log_dest_port", "severity_ordinal",
    "status_bucket", "src_burst_count", "src_distinct_users", "log_message_len",
]
SEVERITY_ORDINAL = {
    Severity.INFO.value: 0, Severity.LOW.value: 1, Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3, Severity.CRITICAL.value: 4,
}

_state_lock = threading.Lock()
_state: dict = {
    "trained": False,
    "model_version": "iforest-v1",
    "trained_at": None,
    "samples": 0,
    "last_run": None,
    "last_flagged": 0,
    "runs": 0,
    "enabled": settings.anomaly_enabled,
    "error": None,
}
_model = None
_scaler_mean: np.ndarray | None = None
_scaler_std: np.ndarray | None = None
_stop = threading.Event()


def _features(event: SecurityEvent, burst: int, distinct_users: int) -> list[float]:
    ts = as_utc(event.ts) or datetime.now(timezone.utc)
    hour = ts.hour + ts.minute / 60.0
    angle = 2 * math.pi * hour / 24.0
    status = event.status_code or 0
    return [
        math.sin(angle),
        math.cos(angle),
        float(ts.weekday()),
        1.0 if (hour >= 22 or hour < 6) else 0.0,
        math.log1p(max(event.bytes_out, 0)),
        math.log1p(max(event.bytes_in, 0)),
        math.log1p(max(event.dest_port or 0, 0)),
        float(SEVERITY_ORDINAL.get(event.severity, 0)),
        float(status // 100),
        math.log1p(burst),
        math.log1p(distinct_users),
        math.log1p(len(event.message or "")),
    ]


def _context_maps(db, events: list[SecurityEvent]) -> tuple[dict, dict]:
    """Per-source burst count and distinct-user count, computed once per batch."""
    burst: dict[str, int] = {}
    users: dict[str, set] = {}
    for e in events:
        if not e.src_ip:
            continue
        burst[e.src_ip] = burst.get(e.src_ip, 0) + 1
        if e.username:
            users.setdefault(e.src_ip, set()).add(e.username)
    return burst, {k: len(v) for k, v in users.items()}


def train(force: bool = False) -> dict:
    """Fit the detector on nominal traffic. Returns a training report."""
    global _model, _scaler_mean, _scaler_std

    started = time.perf_counter()
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # pragma: no cover - scikit-learn is a hard dep
        with _state_lock:
            _state["error"] = f"scikit-learn unavailable: {exc}"
        return dict(_state)

    with session_scope() as db:
        nominal = db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.severity.in_([Severity.INFO.value, Severity.LOW.value]),
                SecurityEvent.matched_rule.is_(None),
            )
            .order_by(SecurityEvent.ts.desc())
            .limit(6_000)
        ).scalars().all()

        if len(nominal) < settings.anomaly_min_samples:
            with _state_lock:
                _state.update(
                    error=(
                        f"only {len(nominal)} nominal samples, need "
                        f"{settings.anomaly_min_samples}"
                    ),
                    trained=False,
                )
            return dict(_state)

        burst, users = _context_maps(db, nominal)
        X = np.array(
            [_features(e, burst.get(e.src_ip or "", 1), users.get(e.src_ip or "", 0)) for e in nominal],
            dtype=np.float64,
        )
        mean = X.mean(axis=0)
        std = X.std(axis=0)
        std[std == 0] = 1.0
        Xs = (X - mean) / std

        model = IsolationForest(
            n_estimators=180,
            contamination=settings.anomaly_contamination,
            max_samples="auto",
            random_state=settings.seed_random_state,
            n_jobs=1,
        )
        model.fit(Xs)

        scores = model.score_samples(Xs)
        duration_ms = int((time.perf_counter() - started) * 1000)
        version = f"iforest-{datetime.now(timezone.utc):%Y%m%d%H%M}"
        metrics = {
            "score_mean": float(scores.mean()),
            "score_std": float(scores.std()),
            "threshold": float(np.percentile(scores, settings.anomaly_contamination * 100)),
            "contamination": settings.anomaly_contamination,
            "n_estimators": 180,
        }

        db.add(
            ModelSnapshot(
                name="anomaly-detector", version=version, samples=len(nominal),
                features=FEATURE_NAMES, metrics=metrics, duration_ms=duration_ms,
            )
        )

    _model, _scaler_mean, _scaler_std = model, mean, std
    with _state_lock:
        _state.update(
            trained=True, model_version=version, trained_at=datetime.now(timezone.utc),
            samples=len(nominal), error=None, metrics=metrics, duration_ms=duration_ms,
        )
    log.info("Anomaly model trained on %d nominal events in %dms", len(nominal), duration_ms)
    return dict(_state)


def score_recent(hours: int = 48, limit: int = 1_500) -> int:
    """Score recent events and persist alerts for the outliers. Returns count."""
    if _model is None or _scaler_mean is None:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    flagged = 0
    with session_scope() as db:
        events = db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.ts >= cutoff)
            .order_by(SecurityEvent.ts.desc())
            .limit(limit)
        ).scalars().all()
        if not events:
            return 0

        already = {
            row[0] for row in db.execute(
                select(AnomalyAlert.event_id).where(AnomalyAlert.event_id.isnot(None))
            ).all()
        }

        burst, users = _context_maps(db, events)
        X = np.array(
            [_features(e, burst.get(e.src_ip or "", 1), users.get(e.src_ip or "", 0)) for e in events],
            dtype=np.float64,
        )
        Xs = (X - _scaler_mean) / _scaler_std
        raw = _model.score_samples(Xs)          # higher = more normal
        preds = _model.predict(Xs)              # -1 = outlier

        # Map to a 0–100 "anomalousness" scale for the UI.
        lo, hi = float(raw.min()), float(raw.max())
        span = (hi - lo) or 1.0

        for idx, (event, score, pred) in enumerate(zip(events, raw, preds)):
            normalised = float((hi - score) / span) * 100.0
            event.anomaly_score = round(normalised, 2)
            event.is_anomaly = bool(pred == -1)
            if pred != -1 or event.id in already:
                continue

            severity = (
                Severity.HIGH.value if normalised >= 85 else
                Severity.MEDIUM.value if normalised >= 65 else Severity.LOW.value
            )
            db.add(
                AnomalyAlert(
                    event_id=event.id,
                    score=round(normalised, 2),
                    severity=severity,
                    model_version=_state["model_version"],
                    reason=_explain(event, normalised),
                    features={
                        name: round(float(value), 4)
                        for name, value in zip(FEATURE_NAMES, X[idx])
                    },
                )
            )
            flagged += 1

    with _state_lock:
        _state.update(last_run=datetime.now(timezone.utc), last_flagged=flagged,
                      runs=_state["runs"] + 1)
    if flagged:
        log.info("Anomaly sweep flagged %d event(s)", flagged)
    return flagged


def _explain(event: SecurityEvent, score: float) -> str:
    ts = as_utc(event.ts)
    reasons = []
    if ts and (ts.hour >= 22 or ts.hour < 6):
        reasons.append(f"activity at {ts:%H:%M} UTC falls outside the 06:00–22:00 nominal window")
    if event.bytes_out > 20_000_000:
        reasons.append(f"egress of {event.bytes_out / 1_048_576:.1f} MiB far exceeds the host baseline")
    if event.dest_port and event.dest_port not in {22, 80, 443, 3306, 5432, 53}:
        reasons.append(f"destination port {event.dest_port} is rare for this environment")
    if event.status_code and event.status_code >= 500:
        reasons.append(f"HTTP {event.status_code} responses are uncommon on this path")
    if event.username and event.username in {"root", "admin", "administrator"}:
        reasons.append(f"privileged principal '{event.username}' involved")
    if not reasons:
        reasons.append(
            "the combination of timing, volume and destination is jointly rare, even though no "
            "single feature is individually extreme"
        )
    return (
        f"Isolation Forest scored this event {score:.0f}/100 for anomalousness. "
        + "; ".join(reasons).capitalize()
        + ". No signature rule matched — this is a purely behavioural detection."
    )


# ---------------------------------------------------------------------------
# Background daemon
# ---------------------------------------------------------------------------
def _loop() -> None:  # pragma: no cover - background thread
    log.info("Anomaly daemon started (interval=%ds)", settings.anomaly_interval_seconds)
    while not _stop.is_set():
        try:
            train()
            score_recent()
        except Exception:
            log.exception("Anomaly sweep failed")
        _stop.wait(settings.anomaly_interval_seconds)
    log.info("Anomaly daemon stopped")


_thread: threading.Thread | None = None


def start_daemon() -> None:
    global _thread
    if not settings.anomaly_enabled or _thread is not None:
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="anomaly-daemon", daemon=True)
    _thread.start()


def stop_daemon() -> None:
    global _thread
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=3)
        _thread = None


def status() -> dict:
    with _state_lock:
        snapshot = dict(_state)
    snapshot["running"] = _thread is not None and _thread.is_alive()
    snapshot["interval_seconds"] = settings.anomaly_interval_seconds
    snapshot["features"] = FEATURE_NAMES
    return snapshot
