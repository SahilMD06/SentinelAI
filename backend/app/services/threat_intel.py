"""Reputation lookups against VirusTotal and AbuseIPDB.

Live mode activates the moment an API key is present. Without keys the module
returns a *deterministic heuristic* verdict derived from the indicator itself —
so demos, tests and offline development produce stable, explainable results
instead of empty responses. Every result is marked `live: true|false` and the
UI surfaces that distinction rather than pretending the data is real.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from ..config import settings
from .cache import cache, cache_backend

log = logging.getLogger("sentinelai.intel")

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

_PRIVATE_HINT = "RFC1918 address — internal asset, no external reputation applies"


def classify_indicator(indicator: str) -> str:
    value = indicator.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(value):
        return "hash"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _verdict_for(score: int) -> str:
    if score >= 80:
        return "malicious"
    if score >= 50:
        return "suspicious"
    if score >= 20:
        return "low-confidence"
    return "clean"


# --------------------------------------------------------------------------
# Deterministic offline scoring
# --------------------------------------------------------------------------
def _heuristic(indicator: str, kind: str) -> dict:
    if kind == "ip" and _is_private(indicator):
        return {
            "provider": "heuristic", "score": 0, "verdict": "internal",
            "detail": _PRIVATE_HINT, "live": False,
            "signals": {"private": True},
        }
    digest = hashlib.blake2b(indicator.encode(), digest_size=8).digest()
    score = digest[0] % 101
    # Bias known-bad-looking traits upward so seeded attacker IPs read as hostile.
    if kind == "ip":
        try:
            first_octet = int(indicator.split(".")[0])
            if first_octet in {45, 185, 194, 91, 103}:  # bulletproof-hosting ranges
                score = max(score, 72 + digest[1] % 25)
        except (ValueError, IndexError):
            pass
    if kind == "hash":
        score = max(score, 55 + digest[2] % 43)
    return {
        "provider": "heuristic",
        "score": int(score),
        "verdict": _verdict_for(int(score)),
        "detail": "Offline deterministic scoring — configure API keys for live data",
        "live": False,
        "signals": {
            "reports": int(digest[3]) % 400,
            "distinct_reporters": int(digest[4]) % 60,
            "first_seen_days": int(digest[5]) % 900,
        },
    }


# --------------------------------------------------------------------------
# Live providers
# --------------------------------------------------------------------------
def _abuseipdb(ip: str) -> dict | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=settings.intel_timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        return {
            "provider": "abuseipdb",
            "score": score,
            "verdict": _verdict_for(score),
            "detail": (
                f"{data.get('totalReports', 0)} reports from "
                f"{data.get('numDistinctUsers', 0)} reporters · "
                f"{data.get('countryCode') or '??'} · {data.get('isp') or 'unknown ISP'}"
            ),
            "live": True,
            "signals": {
                "reports": data.get("totalReports"),
                "distinct_reporters": data.get("numDistinctUsers"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "tor": data.get("isTor"),
                "last_reported": data.get("lastReportedAt"),
            },
        }
    except Exception as exc:  # pragma: no cover - network dependent
        log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


def _virustotal(indicator: str, kind: str) -> dict | None:
    if not settings.virustotal_api_key:
        return None
    path = {"hash": "files", "domain": "domains", "ip": "ip_addresses"}.get(kind)
    if not path:
        return None
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/{path}/{indicator}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=settings.intel_timeout_seconds,
        )
        if resp.status_code == 404:
            return {
                "provider": "virustotal", "score": 0, "verdict": "unknown",
                "detail": "Indicator not present in VirusTotal corpus", "live": True,
                "signals": {},
            }
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        score = min(int(((malicious + 0.5 * suspicious) / total) * 100 * 2.2), 100)
        return {
            "provider": "virustotal",
            "score": score,
            "verdict": _verdict_for(score),
            "detail": f"{malicious}/{total} engines flag this indicator",
            "live": True,
            "signals": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless"),
                "engines": total,
                "reputation": attrs.get("reputation"),
                "type": attrs.get("type_description") or attrs.get("as_owner"),
                "names": (attrs.get("names") or [])[:5],
            },
        }
    except Exception as exc:  # pragma: no cover - network dependent
        log.warning("VirusTotal lookup failed for %s: %s", indicator, exc)
        return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def lookup(indicator: str, *, force_refresh: bool = False, session=None) -> dict:
    """Resolve reputation for one indicator.

    Pass `session` when the caller already holds a transaction — opening a
    second SQLite writer inside an open transaction blocks on its lock.
    """
    indicator = indicator.strip()
    kind = classify_indicator(indicator)
    key = f"intel:{kind}:{indicator.lower()}"

    if not force_refresh:
        cached = cache.get(key)
        if cached:
            cached["cached"] = True
            cached["cache_backend"] = cache_backend()
            return cached

    providers: list[dict] = []
    if kind == "ip" and not _is_private(indicator):
        vt = _virustotal(indicator, kind)
        if vt:
            providers.append(vt)
        abuse = _abuseipdb(indicator)
        if abuse:
            providers.append(abuse)
    elif kind in {"hash", "domain"}:
        vt = _virustotal(indicator, kind)
        if vt:
            providers.append(vt)

    if not providers:
        providers.append(_heuristic(indicator, kind))

    score = max(p["score"] for p in providers)
    live = any(p["live"] for p in providers)
    now = datetime.now(timezone.utc)
    result = {
        "indicator": indicator,
        "indicator_type": kind,
        "verdict": _verdict_for(score) if kind != "unknown" else "unparseable",
        "score": score,
        "providers": providers,
        "live": live,
        "cached": False,
        "cache_backend": cache_backend(),
        "fetched_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=settings.intel_cache_ttl_seconds)).isoformat(),
    }
    cache.set(key, result, settings.intel_cache_ttl_seconds)
    _persist(result, session)
    return result


def _write_records(db, result: dict) -> None:
    from sqlalchemy import select

    from ..models import IntelRecord

    now = datetime.now(timezone.utc)
    for provider in result["providers"]:
        row = db.execute(
            select(IntelRecord).where(
                IntelRecord.indicator == result["indicator"],
                IntelRecord.provider == provider["provider"],
            )
        ).scalar_one_or_none()
        if row is None:
            row = IntelRecord(
                indicator=result["indicator"],
                indicator_type=result["indicator_type"],
                provider=provider["provider"],
            )
            db.add(row)
        row.verdict = provider["verdict"]
        row.score = provider["score"]
        row.live = provider["live"]
        row.payload = provider
        row.fetched_at = now
        row.expires_at = now + timedelta(seconds=settings.intel_cache_ttl_seconds)


def _persist(result: dict, session=None) -> None:
    """Durable mirror so reputation history survives a cache flush."""
    from ..database import session_scope

    try:
        if session is not None:
            _write_records(session, result)
            return
        with session_scope() as db:
            _write_records(db, result)
    except Exception as exc:  # pragma: no cover - non-fatal
        log.debug("Intel persistence skipped: %s", exc)


def status() -> dict:
    return {
        "mode": "live" if settings.intel_live else "heuristic-fallback",
        "virustotal": bool(settings.virustotal_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "cache_backend": cache_backend(),
        "ttl_seconds": settings.intel_cache_ttl_seconds,
    }
