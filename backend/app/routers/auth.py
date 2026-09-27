"""Authentication: password login, session introspection, and OIDC SSO.

Self-registration is deliberately absent — SentinelAI users are provisioned by
an administrator, matching how an enterprise security console is actually
operated. The /register endpoint exists only to return an explicit 403 so the
policy is discoverable rather than a missing route.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import ROLE_LABELS, capabilities_for, get_current_user, record_audit
from ..models import Role, User
from ..schemas import LoginRequest, SessionOut, UserOut
from ..security import create_access_token, hash_password, new_state_token, verify_password

log = logging.getLogger("sentinelai.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

# Deliberate constant-time-ish floor so a missing account and a wrong password
# take indistinguishable wall-clock time.
_MIN_LOGIN_SECONDS = 0.35

DEMO_ACCOUNTS = [
    {"email": "admin@sentinelai.io", "password": "Admin@123", "role": "admin",
     "label": "Administrator", "name": "Priya Raghavan",
     "blurb": "Full platform control, user provisioning, threat simulation"},
    {"email": "manager@sentinelai.io", "password": "Manager@123", "role": "manager",
     "label": "SOC Manager", "name": "Daniel Okonkwo",
     "blurb": "Case assignment, closure authority, all analyst tooling"},
    {"email": "analyst@sentinelai.io", "password": "Analyst@123", "role": "analyst",
     "label": "Security Analyst", "name": "Mei Lin Chen",
     "blurb": "Triage, agent investigations, hunting and Copilot"},
    {"email": "viewer@sentinelai.io", "password": "Viewer@123", "role": "viewer",
     "label": "Viewer", "name": "Tom Alvarez",
     "blurb": "Read-only across the console; all write controls locked"},
]

_sso_states: dict[str, float] = {}


def _session_payload(user: User) -> SessionOut:
    token, expires = create_access_token(
        subject=user.email, role=user.role, user_id=user.id,
        extra={"name": user.full_name, "provider": user.auth_provider},
    )
    return SessionOut(
        access_token=token,
        expires_at=expires,
        user=UserOut.model_validate(user),
        role_label=ROLE_LABELS.get(user.role, user.role),
        capabilities=capabilities_for(user.role),
    )


@router.post("/login", response_model=SessionOut, summary="Password authentication")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> SessionOut:
    started = time.perf_counter()
    email = payload.email.lower().strip()
    user = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()

    def _finish_delay() -> None:
        elapsed = time.perf_counter() - started
        if elapsed < _MIN_LOGIN_SECONDS:
            time.sleep(_MIN_LOGIN_SECONDS - elapsed)

    if user is None or not verify_password(payload.password, user.hashed_password):
        if user is not None:
            user.failed_logins += 1
            record_audit(db, actor=user, action="auth.login.failed",
                         target_type="user", target_id=user.id,
                         detail="Invalid password", request=request)
            db.commit()
        _finish_delay()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        _finish_delay()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Contact your administrator.",
        )

    user.last_login_at = datetime.now(timezone.utc)
    user.failed_logins = 0
    record_audit(db, actor=user, action="auth.login.success",
                 target_type="user", target_id=user.id, request=request)
    db.commit()
    db.refresh(user)
    _finish_delay()
    return _session_payload(user)


@router.get("/me", response_model=SessionOut, summary="Current session")
def me(user: User = Depends(get_current_user)) -> SessionOut:
    return _session_payload(user)


@router.post("/logout", summary="Client-side session teardown")
def logout(request: Request, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)) -> dict:
    record_audit(db, actor=user, action="auth.logout", target_type="user",
                 target_id=user.id, request=request)
    db.commit()
    return {
        "detail": "Session ended. Discard the bearer token client-side.",
        "note": "JWTs are stateless; token lifetime is bounded by its exp claim.",
    }


@router.post("/register", status_code=status.HTTP_403_FORBIDDEN, summary="Disabled by policy")
def register() -> dict:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "Self-registration is disabled. SentinelAI accounts are provisioned by an "
            "administrator through User Management."
        ),
    )


@router.get("/demo-accounts", summary="Seeded evaluation accounts")
def demo_accounts() -> dict:
    return {
        "accounts": DEMO_ACCOUNTS,
        "notice": (
            "These credentials exist only in the seeded evaluation dataset. Rotate the seed "
            "users and set a strong JWT_SECRET before any real deployment."
        ),
        "self_registration": settings.allow_self_registration,
    }


# ---------------------------------------------------------------------------
# SSO / OIDC
# ---------------------------------------------------------------------------
@router.get("/sso/config", summary="SSO availability for the login screen")
def sso_config() -> dict:
    return {
        "enabled": settings.sso_enabled,
        "provider": settings.oidc_provider_name,
        "mode": "live-oidc" if settings.oidc_live else "mock-idp",
        "authorize_url": f"{settings.api_prefix}/auth/sso/login",
        "allowed_domains": settings.sso_allowed_domains,
        "detail": (
            "Live OIDC authorisation-code flow against the configured discovery document."
            if settings.oidc_live else
            "Mock identity provider — exercises the full authorisation-code round trip locally. "
            "Set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_DISCOVERY_URL to point at a real "
            "Okta or Auth0 tenant."
        ),
    }


@router.get("/sso/login", summary="Begin the OIDC authorisation-code flow")
def sso_login(email: str | None = None) -> RedirectResponse:
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO is not enabled on this deployment")

    state = new_state_token()
    _sso_states[state] = time.time()
    # Expire stale states so the dict cannot grow unbounded.
    for key, created in list(_sso_states.items()):
        if time.time() - created > 600:
            _sso_states.pop(key, None)

    if settings.oidc_live:  # pragma: no cover - requires a real IdP
        import httpx

        discovery = httpx.get(settings.oidc_discovery_url, timeout=6).json()
        params = urlencode({
            "client_id": settings.oidc_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": settings.oidc_redirect_uri,
            "state": state,
            "nonce": secrets.token_urlsafe(16),
        })
        return RedirectResponse(f"{discovery['authorization_endpoint']}?{params}")

    # Mock IdP: skip the external round trip but keep the same state/code contract.
    code = f"mock.{secrets.token_urlsafe(12)}"
    params = urlencode({"code": code, "state": state, "email": email or ""})
    return RedirectResponse(f"{settings.api_prefix}/auth/sso/callback?{params}")


@router.get("/sso/callback", summary="OIDC redirect handler")
def sso_callback(
    request: Request,
    code: str,
    state: str,
    email: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    if state not in _sso_states:
        raise HTTPException(status_code=400, detail="Invalid or expired SSO state")
    _sso_states.pop(state, None)

    if settings.oidc_live:  # pragma: no cover - requires a real IdP
        import httpx

        discovery = httpx.get(settings.oidc_discovery_url, timeout=6).json()
        token_resp = httpx.post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            timeout=8,
        )
        token_resp.raise_for_status()
        access = token_resp.json()["access_token"]
        userinfo = httpx.get(
            discovery["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access}"}, timeout=8,
        ).json()
        claim_email = (userinfo.get("email") or "").lower()
        claim_name = userinfo.get("name") or claim_email
        subject = userinfo.get("sub")
    else:
        claim_email = (email or "analyst@sentinelai.io").lower().strip()
        claim_name = claim_email.split("@")[0].replace(".", " ").title()
        subject = f"mock|{claim_email}"

    domain = claim_email.split("@")[-1]
    if settings.sso_allowed_domains and domain not in settings.sso_allowed_domains:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Domain '{domain}' is not federated with this tenant.",
        )

    user = db.execute(select(User).where(func.lower(User.email) == claim_email)).scalar_one_or_none()
    if user is None:
        # Just-in-time provisioning, lowest privilege by default.
        user = User(
            email=claim_email, full_name=claim_name, role=Role.VIEWER.value,
            job_title="SSO Provisioned", team="Federated",
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            auth_provider="oidc", external_subject=subject, is_active=True,
        )
        db.add(user)
        db.flush()
        record_audit(db, actor=user, action="auth.sso.jit_provision",
                     target_type="user", target_id=user.id,
                     detail=f"JIT provisioned from {settings.oidc_provider_name}", request=request)
    else:
        user.auth_provider = "oidc"
        user.external_subject = subject

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated.")

    user.last_login_at = datetime.now(timezone.utc)
    record_audit(db, actor=user, action="auth.sso.login", target_type="user",
                 target_id=user.id, request=request)
    db.commit()
    db.refresh(user)

    session = _session_payload(user)
    fragment = urlencode({"token": session.access_token, "provider": "sso"})
    return RedirectResponse(f"{settings.frontend_url}/auth/callback#{fragment}")
