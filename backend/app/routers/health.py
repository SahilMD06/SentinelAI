"""Liveness, readiness and deep-health probes for orchestrators."""

from __future__ import annotations

import platform
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Response, status

from ..config import settings
from ..database import database_healthy
from ..services import anomaly, threat_intel, tracing
from ..services.cache import cache_status
from ..services.rag import engine as rag_engine

router = APIRouter(tags=["system"])
STARTED_AT = time.time()
VERSION = "1.0.0"


@router.get("/liveness", summary="Process liveness probe")
def liveness() -> dict:
    """Cheapest possible check — the process is up and the event loop responds."""
    return {
        "status": "alive",
        "service": settings.app_name,
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
        "timestamp": datetime.now(timezone.utc),
    }


@router.get("/readiness", summary="Readiness probe (dependency-aware)")
def readiness(response: Response) -> dict:
    db_ok, db_error = database_healthy()
    ready = db_ok and rag_engine.ready
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "not-ready",
        "checks": {
            "database": {"ok": db_ok, "error": db_error,
                         "engine": "postgresql" if settings.is_postgres else "sqlite"},
            "knowledge_index": {"ok": rag_engine.ready, **rag_engine.describe()},
        },
        "timestamp": datetime.now(timezone.utc),
    }


@router.get("/health", summary="Deep health and component inventory")
def health(response: Response) -> dict:
    db_ok, db_error = database_healthy()
    cache = cache_status()
    components = {
        "cache": cache,
        "knowledge_index": rag_engine.describe(),
        "threat_intel": threat_intel.status(),
        "anomaly_detector": anomaly.status(),
        "tracing": tracing.status(),
        "sso": {
            "enabled": settings.sso_enabled,
            "mode": "live-oidc" if settings.oidc_live else "mock-idp",
            "provider": settings.oidc_provider_name,
        },
    }
    healthy = db_ok
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "healthy" if healthy else "degraded",
        "service": settings.app_name,
        "version": VERSION,
        "environment": settings.environment,
        "database": {
            "ok": db_ok,
            "engine": "postgresql" if settings.is_postgres else "sqlite",
            "error": db_error,
        },
        "components": components,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
        "timestamp": datetime.now(timezone.utc),
    }
