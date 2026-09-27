"""Pytest fixtures: a fully seeded, disposable SentinelAI instance per session."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Configure before any app module is imported.
_TMP = Path(tempfile.mkdtemp(prefix="sentinelai-test-"))
os.environ.setdefault("SQLITE_PATH", str(_TMP / "test.db"))
os.environ.setdefault("ANOMALY_ENABLED", "0")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("BCRYPT_ROUNDS", "4")          # keep the suite fast
os.environ.setdefault("SEED_EVENTS", "260")
os.environ.setdefault("SEED_INCIDENTS", "14")
os.environ.setdefault("SEED_INVESTIGATIONS", "4")
os.environ.setdefault("SEED_DOCUMENTS", "110")

# Isolate tests from whatever real .env / live credentials happen to be
# configured on the developer's machine — a test run must never touch a real
# database or make live external calls, regardless of what .env sets.
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
os.environ.setdefault("ABUSEIPDB_API_KEY", "")
os.environ.setdefault("LANGSMITH_API_KEY", "")
os.environ.setdefault("TRACING_EXPORTER", "local")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def _auth(client, email: str, password: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client) -> dict:
    return _auth(client, "admin@sentinelai.io", "Admin@123")


@pytest.fixture(scope="session")
def manager(client) -> dict:
    return _auth(client, "manager@sentinelai.io", "Manager@123")


@pytest.fixture(scope="session")
def analyst(client) -> dict:
    return _auth(client, "analyst@sentinelai.io", "Analyst@123")


@pytest.fixture(scope="session")
def viewer(client) -> dict:
    return _auth(client, "viewer@sentinelai.io", "Viewer@123")


@pytest.fixture(scope="session")
def incident_ref(client, analyst) -> str:
    response = client.get("/api/incidents?size=1&sort=risk_score&order=desc", headers=analyst)
    assert response.status_code == 200
    return response.json()["items"][0]["ref"]
