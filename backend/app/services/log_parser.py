"""Raw-log parsing (ingest) and Lucene-style query parsing (threat hunting)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote_plus

from ..models import Severity

# ---------------------------------------------------------------------------
# Ingest: raw text line → normalised event dict
# ---------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_NGINX_RE = re.compile(
    r"^(?P<ip>[\d.:a-fA-F]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+)(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|for|account)\s+(?:invalid user\s+)?([A-Za-z0-9._\-]+)")
_PORT_RE = re.compile(r"port\s+(\d{1,5})")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}

SIGNATURES: list[tuple[str, str, str, str]] = [
    # (regex, event_type, severity, rule id)
    (r"failed password|authentication failure|invalid user", "auth_failure", Severity.MEDIUM.value, "SIG-AUTH-001"),
    (r"accepted password|accepted publickey|session opened", "auth_success", Severity.INFO.value, "SIG-AUTH-010"),
    (r"possible break-?in attempt|reverse mapping check", "recon", Severity.HIGH.value, "SIG-RECON-004"),
    (r"union\s+select|or\s+1=1|information_schema|sleep\(\d+\)", "sql_injection", Severity.CRITICAL.value, "SIG-WEB-101"),
    (r"\.\./|%2e%2e%2f|etc/passwd", "path_traversal", Severity.HIGH.value, "SIG-WEB-102"),
    (r"<script|onerror=|javascript:", "xss_attempt", Severity.MEDIUM.value, "SIG-WEB-103"),
    (r"cmd\.jsp|shell\.php|eval\(base64_decode", "web_shell", Severity.CRITICAL.value, "SIG-WEB-201"),
    (r"vssadmin.*delete|wbadmin\s+delete|bcdedit.*recoveryenabled", "recovery_inhibit", Severity.CRITICAL.value, "SIG-RANSOM-001"),
    (r"powershell.*-enc|frombase64string", "obfuscated_exec", Severity.HIGH.value, "SIG-EXEC-011"),
    (r"sudo:.*COMMAND=|pkexec", "privilege_use", Severity.MEDIUM.value, "SIG-PRIV-002"),
    (r"useradd|new user|net user .*\/add", "account_created", Severity.HIGH.value, "SIG-PERSIST-003"),
    (r"crontab|systemd timer|schtasks", "scheduled_task", Severity.MEDIUM.value, "SIG-PERSIST-005"),
    (r"port scan|nmap|syn flood", "port_scan", Severity.MEDIUM.value, "SIG-RECON-001"),
    (r"denied|blocked|rejected", "policy_block", Severity.LOW.value, "SIG-FW-001"),
]


def _severity_from_status(status: int) -> str:
    if status >= 500:
        return Severity.HIGH.value
    if status in (401, 403):
        return Severity.MEDIUM.value
    if status == 404:
        return Severity.LOW.value
    return Severity.INFO.value


def _apply_signatures(text: str) -> tuple[str | None, str | None, str | None]:
    """Evaluate the signature set against both the raw and URL-decoded forms.

    Attackers percent-encode payloads precisely to slip past naive matching, so
    `%20UNION%20SELECT%20` must be evaluated as `union select` too.
    """
    candidates = {text.lower()}
    try:
        candidates.add(unquote_plus(text).lower())
    except Exception:  # pragma: no cover - unquote is total in practice
        pass
    for pattern, event_type, severity, rule in SIGNATURES:
        if any(re.search(pattern, candidate) for candidate in candidates):
            return event_type, severity, rule
    return None, None, None


def parse_line(line: str, *, source_hint: str | None = None) -> dict[str, Any] | None:
    """Best-effort normalisation of one raw log line. Returns None if unusable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    now = datetime.now(timezone.utc)
    event: dict[str, Any] = {
        "ts": now,
        "source": source_hint or "manual-upload",
        "host": "unknown",
        "raw": line[:4_000],
        "message": line[:1_000],
        "severity": Severity.INFO.value,
        "event_type": "generic",
        "bytes_in": 0,
        "bytes_out": 0,
    }

    m = _NGINX_RE.match(line)
    if m:
        status = int(m.group("status"))
        event.update(
            source=source_hint or "nginx",
            host="web-edge-01",
            src_ip=m.group("ip"),
            dest_port=443,
            protocol="https",
            username=None if m.group("user") == "-" else m.group("user"),
            status_code=status,
            bytes_out=int(m.group("size")),
            user_agent=(m.group("ua") or "")[:255] or None,
            event_type="http_request",
            severity=_severity_from_status(status),
            message=f'{m.group("method")} {m.group("path")} → {status}',
        )
        try:
            event["ts"] = datetime.strptime(
                m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        etype, sev, rule = _apply_signatures(m.group("path"))
        if etype:
            event.update(event_type=etype, severity=sev, matched_rule=rule)
        return event

    m = _SYSLOG_RE.match(line)
    if m:
        proc = m.group("proc")
        msg = m.group("msg")
        event.update(
            source=source_hint or proc.split("/")[-1],
            host=m.group("host"),
            message=msg[:1_000],
            protocol="tcp",
        )
        try:
            event["ts"] = datetime(
                now.year, _MONTHS[m.group("mon")], int(m.group("day")),
                *(int(p) for p in m.group("time").split(":")), tzinfo=timezone.utc,
            )
        except (ValueError, KeyError):
            pass
        ip = _IP_RE.search(msg)
        if ip:
            event["src_ip"] = ip.group(0)
        user = _USER_RE.search(msg)
        if user:
            event["username"] = user.group(1)
        port = _PORT_RE.search(msg)
        if port:
            event["dest_port"] = int(port.group(1))
        etype, sev, rule = _apply_signatures(msg)
        if etype:
            event.update(event_type=etype, severity=sev, matched_rule=rule)
        return event

    # key=value style (firewall / EDR exports)
    pairs = dict(_KV_RE.findall(line))
    if len(pairs) >= 3:
        for key, value in list(pairs.items()):
            pairs[key] = value.strip('"')
        event.update(
            source=source_hint or pairs.get("devname") or pairs.get("product") or "kv-source",
            host=pairs.get("host") or pairs.get("devname") or "unknown",
            src_ip=pairs.get("srcip") or pairs.get("src") or pairs.get("source_ip"),
            dest_ip=pairs.get("dstip") or pairs.get("dst"),
            username=pairs.get("user") or pairs.get("username"),
            protocol=pairs.get("proto") or pairs.get("protocol"),
            action=pairs.get("action"),
            event_type=pairs.get("type") or pairs.get("event") or "generic",
        )
        for numeric, field in (("dstport", "dest_port"), ("sentbyte", "bytes_out"), ("rcvdbyte", "bytes_in")):
            try:
                event[field] = int(pairs[numeric])
            except (KeyError, ValueError):
                pass
        etype, sev, rule = _apply_signatures(line)
        if etype:
            event.update(event_type=etype, severity=sev, matched_rule=rule)
        return event

    # Unstructured fallback — still extract what we can.
    ip = _IP_RE.search(line)
    if ip:
        event["src_ip"] = ip.group(0)
    etype, sev, rule = _apply_signatures(line)
    if etype:
        event.update(event_type=etype, severity=sev, matched_rule=rule)
    return event


# ---------------------------------------------------------------------------
# Hunting: Lucene-ish query → SQLAlchemy filters
# ---------------------------------------------------------------------------
FIELD_MAP = {
    "src_ip": "src_ip", "source_ip": "src_ip", "ip": "src_ip",
    "dest_ip": "dest_ip", "dst_ip": "dest_ip",
    "host": "host", "user": "username", "username": "username",
    "type": "event_type", "event_type": "event_type",
    "severity": "severity", "source": "source", "rule": "matched_rule",
    "status": "status_code", "port": "dest_port", "country": "geo_country",
    "protocol": "protocol", "action": "action", "hash": "file_hash",
}
NUMERIC_FIELDS = {"status_code", "dest_port", "bytes_out", "bytes_in"}

_TOKEN_RE = re.compile(
    r'(?P<neg>-|NOT\s+)?(?:(?P<field>\w+)\s*(?P<op>>=|<=|:|=|>|<)\s*)?'
    r'(?P<value>"[^"]*"|\S+)',
    re.IGNORECASE,
)


class ParsedQuery:
    def __init__(self) -> None:
        self.terms: list[dict] = []
        self.free_text: list[str] = []
        self.warnings: list[str] = []

    def as_dict(self) -> dict:
        return {
            "filters": self.terms,
            "free_text": self.free_text,
            "warnings": self.warnings,
        }


def parse_query(raw: str) -> ParsedQuery:
    """Supports: field:value, field>=n, quoted phrases, -negation, NOT, wildcards (*)."""
    parsed = ParsedQuery()
    if not raw or not raw.strip():
        return parsed

    for match in _TOKEN_RE.finditer(raw):
        value = match.group("value").strip('"')
        if not value or value.upper() in {"AND", "OR"}:
            continue
        field = (match.group("field") or "").lower()
        op = match.group("op") or ":"
        negated = bool(match.group("neg"))

        if not field:
            parsed.free_text.append(value)
            continue

        column = FIELD_MAP.get(field)
        if column is None:
            parsed.warnings.append(
                f'Unknown field "{field}" — searched as free text. '
                f"Known fields: {', '.join(sorted(set(FIELD_MAP)))}"
            )
            parsed.free_text.append(f"{field}{op}{value}")
            continue

        parsed.terms.append(
            {
                "column": column,
                "op": op,
                "value": value,
                "negated": negated,
                "numeric": column in NUMERIC_FIELDS,
                "wildcard": "*" in value,
            }
        )
    return parsed


def apply_query(stmt, model, parsed: ParsedQuery):
    """Attach parsed filters to a SQLAlchemy select()."""
    from sqlalchemy import not_, or_

    for term in parsed.terms:
        col = getattr(model, term["column"])
        value = term["value"]
        if term["numeric"]:
            try:
                num = int(value)
            except ValueError:
                parsed.warnings.append(f"{term['column']} expects a number, got {value!r}")
                continue
            clause = {
                ">": col > num, ">=": col >= num, "<": col < num, "<=": col <= num,
            }.get(term["op"], col == num)
        elif term["wildcard"]:
            clause = col.ilike(value.replace("*", "%"))
        else:
            clause = col.ilike(value)
        stmt = stmt.where(not_(clause) if term["negated"] else clause)

    for text in parsed.free_text:
        like = f"%{text}%"
        stmt = stmt.where(
            or_(
                model.message.ilike(like),
                model.raw.ilike(like),
                model.src_ip.ilike(like),
                model.username.ilike(like),
                model.host.ilike(like),
                model.event_type.ilike(like),
            )
        )
    return stmt


QUERY_EXAMPLES = [
    ('severity:critical', "Every critical-severity event"),
    ('event_type:auth_failure user:root', "Root authentication failures"),
    ('src_ip:45.* -severity:info', "Anything from 45.0.0.0/8 that is not informational"),
    ('status>=500 source:nginx', "Server errors on the web tier"),
    ('"union select"', "Exact-phrase search for SQL injection payloads"),
    ('host:db-prod-01 NOT event_type:http_request', "Database host, excluding web traffic"),
]
