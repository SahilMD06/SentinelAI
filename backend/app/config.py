"""Central runtime configuration.

Every optional integration is expressed as "configured / not configured" so the
platform boots to a fully working state with zero environment variables while
still lighting up production services the moment credentials appear.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    """Immutable-ish settings object resolved once per process."""

    def __init__(self) -> None:
        # -- Application ------------------------------------------------------
        self.app_name: str = os.getenv("APP_NAME", "SentinelAI")
        self.environment: str = os.getenv("ENVIRONMENT", "development")
        self.debug: bool = _bool("DEBUG", self.environment != "production")
        self.api_prefix: str = "/api"

        # -- Database ---------------------------------------------------------
        # Production: DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db
        # Offline dev: falls back to a local SQLite file next to the backend.
        self.database_url: str = os.getenv("DATABASE_URL", "").strip()
        self.sqlite_path: str = os.getenv("SQLITE_PATH", "sentinel_ai.db")

        # -- Auth -------------------------------------------------------------
        self.jwt_secret: str = os.getenv(
            "JWT_SECRET", "sentinelai-dev-secret-change-me-in-production"
        )
        self.jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
        self.jwt_ttl_minutes: int = _int("JWT_TTL_MINUTES", 720)
        self.bcrypt_rounds: int = _int("BCRYPT_ROUNDS", 12)
        self.allow_self_registration: bool = _bool("ALLOW_SELF_REGISTRATION", False)

        # -- CORS -------------------------------------------------------------
        origins = os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://localhost:3000",
        )
        self.cors_origins: list[str] = [o.strip() for o in origins.split(",") if o.strip()]

        # -- Seeding ----------------------------------------------------------
        self.auto_seed: bool = _bool("AUTO_SEED", True)
        self.seed_events: int = _int("SEED_EVENTS", 640)
        self.seed_documents: int = _int("SEED_DOCUMENTS", 124)
        self.seed_incidents: int = _int("SEED_INCIDENTS", 58)
        self.seed_investigations: int = _int("SEED_INVESTIGATIONS", 24)
        self.seed_random_state: int = _int("SEED_RANDOM_STATE", 20260823)

        # -- Vector store / RAG ----------------------------------------------
        # auto | chroma | faiss | pgvector | tfidf
        self.vector_backend: str = os.getenv("VECTOR_BACKEND", "auto").lower()
        self.embedding_model: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        self.embedding_dim: int = _int("EMBEDDING_DIM", 384)
        self.chroma_path: str = os.getenv("CHROMA_PATH", ".chroma")
        self.rag_top_k: int = _int("RAG_TOP_K", 5)

        # -- Anomaly detection ------------------------------------------------
        self.anomaly_enabled: bool = _bool("ANOMALY_ENABLED", True)
        self.anomaly_interval_seconds: int = _int("ANOMALY_INTERVAL_SECONDS", 300)
        self.anomaly_contamination: float = float(
            os.getenv("ANOMALY_CONTAMINATION", "0.06")
        )
        self.anomaly_min_samples: int = _int("ANOMALY_MIN_SAMPLES", 60)

        # -- Threat intel -----------------------------------------------------
        self.virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.intel_timeout_seconds: float = float(os.getenv("INTEL_TIMEOUT_SECONDS", "6"))
        self.intel_cache_ttl_seconds: int = _int("INTEL_CACHE_TTL_SECONDS", 86_400)

        # -- Cache ------------------------------------------------------------
        # Upstash works out of the box: REDIS_URL=rediss://default:pass@host:6379
        self.redis_url: str = os.getenv("REDIS_URL", "").strip()

        # -- Tracing ----------------------------------------------------------
        # local | langsmith | phoenix
        self.tracing_exporter: str = os.getenv("TRACING_EXPORTER", "local").lower()
        self.tracing_project: str = os.getenv("TRACING_PROJECT", "sentinelai")
        self.langsmith_api_key: str = os.getenv("LANGSMITH_API_KEY", "").strip()
        self.phoenix_endpoint: str = os.getenv("PHOENIX_COLLECTOR_ENDPOINT", "").strip()
        self.trace_buffer_size: int = _int("TRACE_BUFFER_SIZE", 2_000)

        # -- SSO / OIDC -------------------------------------------------------
        self.sso_enabled: bool = _bool("SSO_ENABLED", True)
        self.oidc_provider_name: str = os.getenv("OIDC_PROVIDER_NAME", "Okta (Mock IdP)")
        self.oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "").strip()
        self.oidc_client_secret: str = os.getenv("OIDC_CLIENT_SECRET", "").strip()
        self.oidc_discovery_url: str = os.getenv("OIDC_DISCOVERY_URL", "").strip()
        self.oidc_redirect_uri: str = os.getenv(
            "OIDC_REDIRECT_URI", "http://localhost:8000/api/auth/sso/callback"
        )
        self.frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
        self.sso_allowed_domains: list[str] = [
            d.strip().lower()
            for d in os.getenv("SSO_ALLOWED_DOMAINS", "sentinelai.io").split(",")
            if d.strip()
        ]

    # -- Derived ------------------------------------------------------------
    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            url = self.database_url
            # Render/Heroku hand out the legacy `postgres://` scheme.
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+psycopg://", 1)
            elif url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+psycopg://", 1)
            return url
        return f"sqlite:///{self.sqlite_path}"

    @property
    def is_postgres(self) -> bool:
        return self.resolved_database_url.startswith("postgresql")

    @property
    def intel_live(self) -> bool:
        return bool(self.virustotal_api_key or self.abuseipdb_api_key)

    @property
    def oidc_live(self) -> bool:
        return bool(self.oidc_client_id and self.oidc_discovery_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()