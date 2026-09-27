"""Small cross-cutting helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on round-trip; normalise everything to aware UTC so
    arithmetic between stored and freshly-created datetimes never raises."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def minutes_between(start: datetime | None, end: datetime | None) -> int:
    a, b = as_utc(start), as_utc(end)
    if not a or not b:
        return 0
    return int((b - a).total_seconds() / 60)


def humanize_bytes(value: int) -> str:
    step = 1024.0
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < step:
            return f"{amount:.1f} {unit}"
        amount /= step
    return f"{amount:.1f} PiB"


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))
