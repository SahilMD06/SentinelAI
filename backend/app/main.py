"""SentinelAI API entrypoint."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import init_db
from .routers import (
    anomaly,
    auth,
    compliance,
    copilot,
    dashboard,
    events,
    health,
    hunting,
    incidents,
    intel,
    tracing,
    users,
)
from .services import anomaly as anomaly_service
from .services.agent_pipeline import AGENT_CATALOG

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)-26s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentinelai")

DESCRIPTION = """
**SentinelAI** is an intelligent SecOps and incident-response platform.

* **Nine-agent investigation pipeline** — log analysis, threat intel, correlation, risk
  scoring, ATT&CK mapping, root-cause analysis, playbook selection, compliance mapping and
  executive reporting, executed as a stateful graph with a full audit trail.
* **Semantic RAG** over MITRE guidance, response playbooks, CVE records and internal policy.
* **Unsupervised anomaly detection** running continuously alongside signature matching.
* **Threat-intel enrichment** with VirusTotal and AbuseIPDB, cached to respect rate limits.
* **Agentic observability** — token spend, latency and prompt/response capture per agent hop.

Authenticate at `POST /api/auth/login`, then send `Authorization: Bearer <token>`.
Seeded evaluation accounts are listed at `GET /api/auth/demo-accounts`.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting %s (%s)", settings.app_name, settings.environment)
    init_db()

    if settings.auto_seed:
        from .seed import seed_if_empty

        result = seed_if_empty()
        if result.get("seeded"):
            log.info("Database seeded: %s", {k: v for k, v in result.items() if k != "rag"})
        else:
            log.info("Seed skipped: %s", result.get("reason"))

    # Build the retrieval index (a no-op rebuild if seeding already did it).
    from .services.rag import engine as rag_engine, rebuild_from_db

    if not rag_engine.ready:
        rebuild_from_db()

    if settings.anomaly_enabled:
        anomaly_service.start_daemon()

    log.info("SentinelAI ready — docs at /docs")
    yield

    anomaly_service.stop_daemon()
    log.info("SentinelAI shut down cleanly")


app = FastAPI(
    title=settings.app_name,
    description=DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Response-Time-Ms"],
)
app.add_middleware(GZipMiddleware, minimum_size=1_000)


@app.middleware("http")
async def timing_and_security_headers(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Response-Time-Ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):  # pragma: no cover
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error.",
            "path": request.url.path,
            "type": type(exc).__name__,
        },
    )


# -- routers ----------------------------------------------------------------
app.include_router(health.router)                       # /health /readiness /liveness
prefix = settings.api_prefix
app.include_router(health.router, prefix=prefix, include_in_schema=False)
app.include_router(auth.router, prefix=prefix)
app.include_router(users.router, prefix=prefix)
app.include_router(dashboard.router, prefix=prefix)
app.include_router(incidents.router, prefix=prefix)
app.include_router(events.router, prefix=prefix)
app.include_router(hunting.router, prefix=prefix)
app.include_router(compliance.router, prefix=prefix)
app.include_router(intel.router, prefix=prefix)
app.include_router(anomaly.router, prefix=prefix)
app.include_router(tracing.router, prefix=prefix)
app.include_router(copilot.router, prefix=prefix)


@app.get("/", tags=["system"], summary="Service banner")
def root() -> dict:
    return {
        "service": settings.app_name,
        "version": "1.0.0",
        "environment": settings.environment,
        "docs": "/docs",
        "api_prefix": prefix,
        "agents": [a["name"] for a in AGENT_CATALOG],
        "endpoints": {
            "login": f"{prefix}/auth/login",
            "demo_accounts": f"{prefix}/auth/demo-accounts",
            "health": "/health",
            "readiness": "/readiness",
            "liveness": "/liveness",
        },
    }


@app.get(f"{settings.api_prefix}/meta", tags=["system"], summary="Client bootstrap metadata")
def meta() -> dict:
    from .deps import ROLE_CAPABILITIES, ROLE_LABELS
    from .routers.incidents import SCENARIOS
    from .services.rag import engine as rag_engine

    return {
        "app": settings.app_name,
        "version": "1.0.0",
        "environment": settings.environment,
        "agents": AGENT_CATALOG,
        "roles": {k: {"label": ROLE_LABELS[k], "capabilities": v}
                  for k, v in ROLE_CAPABILITIES.items()},
        "scenarios": [{"key": k, "title": v["title"], "category": v["category"]}
                      for k, v in SCENARIOS.items()],
        "knowledge_index": rag_engine.describe(),
        "features": {
            "sso": settings.sso_enabled,
            "self_registration": settings.allow_self_registration,
            "anomaly_detection": settings.anomaly_enabled,
            "live_threat_intel": settings.intel_live,
        },
    }
