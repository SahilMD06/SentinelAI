"""Authentication, JWT handling and RBAC enforcement."""

from __future__ import annotations

import jwt
import pytest

from app.config import settings
from app.deps import ROLE_CAPABILITIES
from app.security import decode_access_token, hash_password, verify_password


def test_bcrypt_roundtrip():
    hashed = hash_password("Analyst@123")
    assert hashed.startswith("$2")
    assert verify_password("Analyst@123", hashed)
    assert not verify_password("Analyst@124", hashed)


def test_bcrypt_handles_passwords_over_72_bytes():
    long_password = "A" * 200 + "!9z"
    hashed = hash_password(long_password)
    assert verify_password(long_password, hashed)
    # The 72-byte truncation bug would make this pass; the SHA-256 pre-hash prevents it.
    assert not verify_password("A" * 200 + "!9y", hashed)


def test_login_issues_signed_jwt(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@sentinelai.io", "password": "Analyst@123"},
    )
    assert response.status_code == 200
    body = response.json()
    claims = decode_access_token(body["access_token"])
    assert claims["sub"] == "analyst@sentinelai.io"
    assert claims["role"] == "analyst"
    assert claims["iss"] == "sentinelai"
    assert body["role_label"] == "Security Analyst"
    assert set(body["capabilities"]) == set(ROLE_CAPABILITIES["analyst"])


def test_login_rejects_bad_password(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@sentinelai.io", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_login_is_case_insensitive_on_email(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "ANALYST@SentinelAI.io", "password": "Analyst@123"},
    )
    assert response.status_code == 200


def test_protected_route_requires_token(client):
    assert client.get("/api/incidents").status_code == 401


def test_tampered_token_rejected(client, analyst):
    forged = jwt.encode(
        {"sub": "analyst@sentinelai.io", "uid": 3, "role": "admin",
         "iss": "sentinelai", "aud": "sentinelai-console", "exp": 9_999_999_999},
        "not-the-real-secret",
        algorithm=settings.jwt_algorithm,
    )
    response = client.get("/api/incidents", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_self_registration_is_disabled(client):
    response = client.post("/api/auth/register")
    assert response.status_code == 403
    assert "provisioned by an administrator" in response.json()["detail"]


def test_demo_accounts_are_published(client):
    body = client.get("/api/auth/demo-accounts").json()
    assert len(body["accounts"]) == 4
    assert {a["role"] for a in body["accounts"]} == {"admin", "manager", "analyst", "viewer"}


@pytest.mark.parametrize(
    "role_fixture,expected",
    [("viewer", 403), ("analyst", 403), ("admin", 201)],
)
def test_user_provisioning_is_admin_only(client, request, role_fixture, expected):
    headers = request.getfixturevalue(role_fixture)
    response = client.post(
        "/api/users",
        headers=headers,
        json={
            "email": f"probe-{role_fixture}@sentinelai.io",
            "full_name": f"Probe {role_fixture}",
            "password": "Str0ng@Passw0rd",
            "role": "viewer",
        },
    )
    assert response.status_code == expected


def test_admin_cannot_demote_last_admin(client, admin):
    users = client.get("/api/users?role=admin", headers=admin).json()
    target = users[0]
    response = client.patch(f"/api/users/{target['id']}", headers=admin, json={"role": "analyst"})
    assert response.status_code == 400


def test_sso_config_reports_mock_mode(client):
    body = client.get("/api/auth/sso/config").json()
    assert body["enabled"] is True
    assert body["mode"] in {"mock-idp", "live-oidc"}


def test_sso_flow_provisions_and_redirects(client):
    start = client.get(
        "/api/auth/sso/login?email=federated.user@sentinelai.io", follow_redirects=False
    )
    assert start.status_code in (302, 307)
    callback = client.get(start.headers["location"], follow_redirects=False)
    assert callback.status_code in (302, 307)
    assert "token=" in callback.headers["location"]


def test_sso_rejects_unfederated_domain(client):
    start = client.get(
        "/api/auth/sso/login?email=outsider@evil.example", follow_redirects=False
    )
    callback = client.get(start.headers["location"], follow_redirects=False)
    assert callback.status_code == 403
