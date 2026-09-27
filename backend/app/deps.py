"""Auth + RBAC dependency helpers shared by every router."""

from __future__ import annotations

from collections.abc import Callable, Iterable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import AuditLog, Role, User
from .security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False, description="SentinelAI JWT")

# Capability matrix — the single source of truth the frontend mirrors.
ROLE_CAPABILITIES: dict[str, list[str]] = {
    Role.ADMIN.value: [
        "incidents:read", "incidents:write", "incidents:assign", "incidents:close",
        "events:read", "events:ingest", "hunt:read", "hunt:save",
        "agents:run", "agents:read", "simulate:run",
        "compliance:read", "compliance:write", "reports:export",
        "users:read", "users:write", "settings:write",
        "copilot:chat", "intel:lookup", "tracing:read", "anomaly:read", "anomaly:write",
    ],
    Role.MANAGER.value: [
        "incidents:read", "incidents:write", "incidents:assign", "incidents:close",
        "events:read", "events:ingest", "hunt:read", "hunt:save",
        "agents:run", "agents:read",
        "compliance:read", "reports:export",
        "users:read",
        "copilot:chat", "intel:lookup", "tracing:read", "anomaly:read", "anomaly:write",
    ],
    Role.ANALYST.value: [
        "incidents:read", "incidents:write",
        "events:read", "events:ingest", "hunt:read", "hunt:save",
        "agents:run", "agents:read",
        "compliance:read", "reports:export",
        "copilot:chat", "intel:lookup", "tracing:read", "anomaly:read", "anomaly:write",
    ],
    Role.VIEWER.value: [
        "incidents:read", "events:read", "hunt:read", "agents:read",
        "compliance:read", "reports:export", "tracing:read", "anomaly:read",
    ],
}

ROLE_LABELS = {
    Role.ADMIN.value: "Administrator",
    Role.MANAGER.value: "SOC Manager",
    Role.ANALYST.value: "Security Analyst",
    Role.VIEWER.value: "Viewer",
}


def capabilities_for(role: str) -> list[str]:
    return ROLE_CAPABILITIES.get(role, ROLE_CAPABILITIES[Role.VIEWER.value])


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Missing bearer token")
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise _unauthorized("Session expired — please sign in again") from exc
    except jwt.PyJWTError as exc:
        raise _unauthorized("Invalid authentication token") from exc

    user = db.get(User, payload.get("uid"))
    if user is None or user.email != payload.get("sub"):
        raise _unauthorized("Token subject no longer provisioned")
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated. Contact your SentinelAI administrator.",
        )
    return user


def require_roles(*roles: str) -> Callable[..., User]:
    allowed = {r.value if isinstance(r, Role) else r for r in roles}

    def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(sorted(allowed))}",
            )
        return user

    return _guard


def require_capability(capability: str) -> Callable[..., User]:
    def _guard(user: User = Depends(get_current_user)) -> User:
        if capability not in capabilities_for(user.role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Your role ({ROLE_LABELS.get(user.role, user.role)}) is read-only "
                    f"for this action ({capability})."
                ),
            )
        return user

    return _guard


require_admin = require_roles(Role.ADMIN.value)


def record_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    target_type: str = "",
    target_id: str | int = "",
    detail: str = "",
    request: Request | None = None,
) -> None:
    entry = AuditLog(
        actor_id=getattr(actor, "id", None),
        actor_email=getattr(actor, "email", "system"),
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        detail=detail,
        ip=(request.client.host if request and request.client else None),
    )
    db.add(entry)


def paginate(items: Iterable, page: int, size: int):
    data = list(items)
    start = (page - 1) * size
    return data[start : start + size], len(data)
