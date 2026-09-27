"""Password hashing (native bcrypt) and JWT issuing/verification."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import settings

_BCRYPT_MAX_BYTES = 72


def _prehash(password: str) -> bytes:
    """bcrypt silently truncates beyond 72 bytes; SHA-256 pre-hash removes the
    ceiling without weakening short passwords."""
    raw = password.encode("utf-8")
    if len(raw) <= _BCRYPT_MAX_BYTES:
        return raw
    return hashlib.sha256(raw).hexdigest().encode("utf-8")


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(_prehash(password), salt).decode("utf-8")


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    *, subject: str, role: str, user_id: int, extra: dict | None = None
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.jwt_ttl_minutes)
    payload: dict = {
        "sub": subject,
        "uid": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "iss": "sentinelai",
        "aud": "sentinelai-console",
        "jti": uuid.uuid4().hex,
    }
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError subclasses on any validation failure."""
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        audience="sentinelai-console",
        issuer="sentinelai",
    )


def new_state_token() -> str:
    return secrets.token_urlsafe(24)
