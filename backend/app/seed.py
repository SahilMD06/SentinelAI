"""Idempotent first-boot seeding.

Runs only when the database is empty. Produces a corpus large and varied enough
that every screen in the console has something real to show: 4 provisioned
users, 600+ security events across four log sources, a 120+ document knowledge
base, 50+ incidents with playbooks, 20+ completed agent investigations, and a
full ISO 27001 / SOC 2 control register.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .database import session_scope
from .models import (
    ComplianceControl,
    Incident,
    IncidentNote,
    IncidentStatus,
    KnowledgeDoc,
    PlaybookItem,
    Role,
    SavedHunt,
    SecurityEvent,
    Severity,
    User,
)
from .security import hash_password
from .services import mitre, playbooks

log = logging.getLogger("sentinelai.seed")

DEMO_USERS = [
    {
        "email": "admin@sentinelai.io", "password": "Admin@123", "role": Role.ADMIN.value,
        "full_name": "Priya Raghavan", "job_title": "Head of Security Engineering",
        "team": "Security Engineering",
    },
    {
        "email": "manager@sentinelai.io", "password": "Manager@123", "role": Role.MANAGER.value,
        "full_name": "Daniel Okonkwo", "job_title": "SOC Manager",
        "team": "Security Operations",
    },
    {
        "email": "analyst@sentinelai.io", "password": "Analyst@123", "role": Role.ANALYST.value,
        "full_name": "Mei Lin Chen", "job_title": "Senior Security Analyst (Tier 2)",
        "team": "Security Operations",
    },
    {
        "email": "viewer@sentinelai.io", "password": "Viewer@123", "role": Role.VIEWER.value,
        "full_name": "Tom Alvarez", "job_title": "IT Risk & Audit",
        "team": "Governance, Risk & Compliance",
    },
]

HOSTS = [
    ("web-edge-01", "nginx", "critical"), ("web-edge-02", "nginx", "critical"),
    ("app-prod-01", "app", "high"), ("app-prod-02", "app", "high"),
    ("db-prod-01", "postgres", "critical"), ("db-replica-01", "postgres", "high"),
    ("bastion-01", "sshd", "critical"), ("build-runner-03", "sshd", "medium"),
    ("file-share-01", "smb", "high"), ("vpn-gw-01", "firewall", "critical"),
    ("workstation-142", "winauth", "low"), ("workstation-088", "winauth", "low"),
    ("k8s-node-07", "kubelet", "medium"), ("mail-relay-01", "postfix", "high"),
]

HOSTILE_IPS = [
    "45.155.205.233", "185.220.101.47", "194.26.229.118", "91.240.118.172",
    "103.149.28.90", "45.9.148.212", "185.156.73.54", "89.248.165.191",
    "5.188.206.130", "141.98.10.63",
]
INTERNAL_IPS = [f"10.20.{s}.{h}" for s in (10, 11, 20, 30) for h in (12, 24, 31, 47, 88, 105)]
BENIGN_IPS = [
    "34.117.59.81", "142.250.185.78", "52.94.236.248", "104.18.32.115",
    "20.42.65.92", "13.107.42.14",
]

USERNAMES = [
    "root", "admin", "administrator", "postgres", "deploy", "jenkins", "svc_backup",
    "m.chen", "d.okonkwo", "p.raghavan", "t.alvarez", "s.patel", "j.novak", "oracle",
    "ubuntu", "test", "guest", "ftpuser",
]
COUNTRIES = ["RU", "CN", "NL", "US", "DE", "BR", "IN", "VN", "RO", "GB"]

WEB_PATHS_BENIGN = [
    "/", "/api/v2/orders", "/api/v2/customers", "/static/app.4f2a.js", "/health",
    "/api/v2/reports/monthly", "/login", "/assets/logo.svg", "/api/v2/inventory",
]
WEB_PATHS_HOSTILE = [
    "/admin.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/index.php?page=../../../../etc/passwd",
    "/wp-admin/setup-config.php",
    "/uploads/cmd.jsp?c=whoami",
    "/api/v2/export?format=<script>alert(1)</script>",
    "/.env",
    "/.git/config",
    "/cgi-bin/luci/;stok=/locale?form=country",
    "/api/v2/users?id=1' OR '1'='1",
]
USER_AGENTS_BENIGN = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
    "SentinelAI-HealthCheck/1.2",
]
USER_AGENTS_HOSTILE = [
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Mozilla/5.0 zgrab/0.x",
    "python-requests/2.31.0",
    "Nikto/2.5.0",
    "curl/8.4.0",
]

INCIDENT_TEMPLATES = [
    {
        "category": "brute-force", "detection": "signature",
        "title": "SSH brute-force against {asset} from {ip}",
        "summary": (
            "A sustained burst of SSH authentication failures targeting multiple accounts on "
            "{asset} originated from {ip}. Rate and account spread are consistent with automated "
            "credential guessing rather than user error."
        ),
        "tags": ["ssh", "authentication", "external"],
    },
    {
        "category": "credential-access", "detection": "correlation",
        "title": "Password spraying across {count} accounts from {ip}",
        "summary": (
            "Low-volume authentication failures spread across a wide account population from "
            "{ip}, staying under per-account lockout thresholds. Classic spray pattern."
        ),
        "tags": ["password-spray", "identity"],
    },
    {
        "category": "web-exploit", "detection": "waf",
        "title": "SQL injection attempts on {asset}",
        "summary": (
            "Requests containing UNION SELECT payloads reached {asset} from {ip}. Several "
            "produced 500-class responses, indicating the payload altered query execution."
        ),
        "tags": ["owasp-a03", "web", "injection"],
    },
    {
        "category": "web-exploit", "detection": "file-integrity",
        "title": "Suspected web shell deployed on {asset}",
        "summary": (
            "A previously unseen script appeared under the web root on {asset} and was "
            "subsequently requested with command parameters from {ip}."
        ),
        "tags": ["web-shell", "persistence"],
    },
    {
        "category": "data-exfiltration", "detection": "dlp",
        "title": "Anomalous outbound transfer from {asset}",
        "summary": (
            "{asset} transferred an unusually large volume to {ip}, well outside the 30-day "
            "egress baseline for this host and outside business hours."
        ),
        "tags": ["exfiltration", "dlp", "data-loss"],
    },
    {
        "category": "ransomware", "detection": "edr",
        "title": "Ransomware precursor activity on {asset}",
        "summary": (
            "Shadow-copy deletion and rapid file-rename activity observed on {asset}. This is "
            "the standard pre-encryption sequence and demands immediate isolation."
        ),
        "tags": ["ransomware", "impact", "urgent"],
    },
    {
        "category": "privilege-escalation", "detection": "audit",
        "title": "Unexpected privilege elevation on {asset}",
        "summary": (
            "Account {user} obtained root on {asset} via a path not present in the approved "
            "elevation matrix."
        ),
        "tags": ["privilege", "audit"],
    },
    {
        "category": "lateral-movement", "detection": "correlation",
        "title": "East-west SSH movement from {asset}",
        "summary": (
            "SSH sessions initiated from {asset} to hosts it has no operational relationship "
            "with, using credentials harvested earlier in the chain."
        ),
        "tags": ["lateral", "segmentation"],
    },
    {
        "category": "reconnaissance", "detection": "signature",
        "title": "Port and path enumeration from {ip}",
        "summary": (
            "Systematic probing of {count} distinct ports and paths from {ip} across the "
            "external estate — pre-attack surface mapping."
        ),
        "tags": ["recon", "scanning"],
    },
    {
        "category": "policy-violation", "detection": "inventory",
        "title": "Unsanctioned remote-access tool on {asset}",
        "summary": (
            "An unapproved RMM agent was found running on {asset} and beaconing to its vendor "
            "control plane. Likely shadow IT, but indistinguishable from operator tooling."
        ),
        "tags": ["policy", "shadow-it"],
    },
    {
        "category": "availability", "detection": "telemetry",
        "title": "Request flood degrading {asset}",
        "summary": (
            "Sustained request volume from {ip} pushed {asset} past its error budget, with 503 "
            "rates breaching the availability SLO."
        ),
        "tags": ["dos", "availability"],
    },
    {
        "category": "persistence", "detection": "audit",
        "title": "Unauthorised scheduled task created on {asset}",
        "summary": (
            "A cron entry was added on {asset} outside the configuration-management pipeline, "
            "invoking an interpreter against a remote payload."
        ),
        "tags": ["persistence", "cron"],
    },
]

ISO_CONTROLS = [
    ("A.5.1", "Organizational controls", "Policies for information security"),
    ("A.5.7", "Organizational controls", "Threat intelligence"),
    ("A.5.15", "Organizational controls", "Access control"),
    ("A.5.16", "Organizational controls", "Identity management"),
    ("A.5.17", "Organizational controls", "Authentication information"),
    ("A.5.23", "Organizational controls", "Information security for cloud services"),
    ("A.5.24", "Organizational controls", "Incident management planning and preparation"),
    ("A.5.25", "Organizational controls", "Assessment and decision on security events"),
    ("A.5.26", "Organizational controls", "Response to information security incidents"),
    ("A.5.27", "Organizational controls", "Learning from information security incidents"),
    ("A.5.28", "Organizational controls", "Collection of evidence"),
    ("A.5.29", "Organizational controls", "Information security during disruption"),
    ("A.5.30", "Organizational controls", "ICT readiness for business continuity"),
    ("A.5.34", "Organizational controls", "Privacy and protection of PII"),
    ("A.6.3", "People controls", "Information security awareness and training"),
    ("A.6.8", "People controls", "Information security event reporting"),
    ("A.7.4", "Physical controls", "Physical security monitoring"),
    ("A.8.1", "Technological controls", "User endpoint devices"),
    ("A.8.2", "Technological controls", "Privileged access rights"),
    ("A.8.3", "Technological controls", "Information access restriction"),
    ("A.8.5", "Technological controls", "Secure authentication"),
    ("A.8.6", "Technological controls", "Capacity management"),
    ("A.8.7", "Technological controls", "Protection against malware"),
    ("A.8.8", "Technological controls", "Management of technical vulnerabilities"),
    ("A.8.9", "Technological controls", "Configuration management"),
    ("A.8.10", "Technological controls", "Information deletion"),
    ("A.8.11", "Technological controls", "Data masking"),
    ("A.8.12", "Technological controls", "Data leakage prevention"),
    ("A.8.13", "Technological controls", "Information backup"),
    ("A.8.15", "Technological controls", "Logging"),
    ("A.8.16", "Technological controls", "Monitoring activities"),
    ("A.8.17", "Technological controls", "Clock synchronisation"),
    ("A.8.20", "Technological controls", "Networks security"),
    ("A.8.21", "Technological controls", "Security of network services"),
    ("A.8.22", "Technological controls", "Segregation of networks"),
    ("A.8.23", "Technological controls", "Web filtering"),
    ("A.8.24", "Technological controls", "Use of cryptography"),
    ("A.8.25", "Technological controls", "Secure development life cycle"),
    ("A.8.26", "Technological controls", "Application security requirements"),
    ("A.8.28", "Technological controls", "Secure coding"),
    ("A.8.29", "Technological controls", "Security testing in development"),
    ("A.8.31", "Technological controls", "Separation of environments"),
    ("A.8.32", "Technological controls", "Change management"),
]

SOC2_CONTROLS = [
    ("CC1.1", "Control environment", "Commitment to integrity and ethical values"),
    ("CC1.4", "Control environment", "Commitment to competence"),
    ("CC2.1", "Communication", "Quality information for internal control"),
    ("CC3.2", "Risk assessment", "Identification and analysis of risks"),
    ("CC3.4", "Risk assessment", "Assessment of fraud risk"),
    ("CC4.1", "Monitoring", "Ongoing and separate evaluations"),
    ("CC5.2", "Control activities", "Technology general controls"),
    ("CC6.1", "Logical access", "Logical access security software and infrastructure"),
    ("CC6.2", "Logical access", "Registration and authorisation of users"),
    ("CC6.3", "Logical access", "Role-based access and least privilege"),
    ("CC6.6", "Logical access", "Boundary protection measures"),
    ("CC6.7", "Logical access", "Restriction of data transmission"),
    ("CC6.8", "Logical access", "Prevention of unauthorised software"),
    ("CC7.1", "System operations", "Detection of configuration and vulnerability changes"),
    ("CC7.2", "System operations", "Monitoring for anomalies"),
    ("CC7.3", "System operations", "Evaluation of security events"),
    ("CC7.4", "System operations", "Incident response programme"),
    ("CC7.5", "System operations", "Recovery from identified incidents"),
    ("CC8.1", "Change management", "Authorised changes to infrastructure and software"),
    ("CC9.1", "Risk mitigation", "Business disruption risk mitigation"),
    ("CC9.2", "Risk mitigation", "Vendor and business partner risk"),
    ("A1.1", "Availability", "Capacity planning and monitoring"),
    ("A1.2", "Availability", "Recovery infrastructure and backups"),
    ("A1.3", "Availability", "Recovery plan testing"),
    ("C1.1", "Confidentiality", "Identification of confidential information"),
    ("C1.2", "Confidentiality", "Disposal of confidential information"),
    ("PI1.1", "Processing integrity", "Processing accuracy and completeness"),
]

CVES = [
    ("CVE-2024-3094", "XZ Utils backdoor in liblzma", 10.0,
     "A malicious upstream commit introduced a backdoor into liblzma affecting sshd via "
     "systemd linkage, permitting pre-authentication remote code execution on affected builds."),
    ("CVE-2023-4863", "libwebp heap buffer overflow", 8.8,
     "A heap overflow in WebP decoding reachable from any renderer that processes untrusted "
     "images; widely exploited in the wild via browsers and messaging clients."),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset", 7.5,
     "Rapid stream cancellation in HTTP/2 permits a denial-of-service amplification against "
     "servers that do not bound concurrent stream churn."),
    ("CVE-2021-44228", "Log4Shell JNDI injection", 10.0,
     "Log4j 2 evaluates JNDI lookups inside logged strings, giving unauthenticated remote code "
     "execution wherever attacker-controlled text reaches a log statement."),
    ("CVE-2024-21762", "FortiOS SSL VPN out-of-bounds write", 9.8,
     "An out-of-bounds write in the SSL VPN daemon allows unauthenticated remote code "
     "execution on internet-facing appliances."),
    ("CVE-2023-34362", "MOVEit Transfer SQL injection", 9.8,
     "SQL injection in the MOVEit Transfer web interface leading to database access and "
     "web shell deployment; exploited at scale for mass data theft."),
    ("CVE-2022-22965", "Spring4Shell", 9.8,
     "Class-loader manipulation in Spring beans binding permits remote code execution on "
     "affected JDK 9+ deployments packaged as WAR."),
    ("CVE-2024-6387", "regreSSHion — OpenSSH signal handler race", 8.1,
     "A race condition in the OpenSSH server signal handler allows unauthenticated remote "
     "code execution as root on glibc-based Linux systems."),
    ("CVE-2023-22515", "Confluence broken access control", 10.0,
     "Broken access control permits creation of unauthorised administrator accounts on "
     "internet-facing Confluence Data Center instances."),
    ("CVE-2024-23897", "Jenkins arbitrary file read", 9.8,
     "The Jenkins CLI expands @-prefixed arguments, allowing unauthenticated arbitrary file "
     "read that escalates to full compromise via credential theft."),
    ("CVE-2023-38831", "WinRAR spoofed archive extension", 7.8,
     "Crafted archives cause WinRAR to execute an attacker script when the user opens a "
     "benign-looking file, used in targeted phishing campaigns."),
    ("CVE-2022-0847", "Dirty Pipe", 7.8,
     "A flaw in the Linux pipe implementation permits overwriting data in read-only files, "
     "yielding straightforward local privilege escalation to root."),
]

POLICY_DOCS = [
    ("Incident severity matrix",
     "P1 covers confirmed compromise of a critical asset or any confirmed data exposure, with a "
     "15-minute containment SLA and mandatory executive notification. P2 covers attempted "
     "compromise of a critical asset or confirmed compromise of a non-critical asset, 1-hour "
     "SLA. P3 covers policy violations and unsuccessful attacks, 8-hour SLA. P4 is "
     "informational with next-business-day handling. Severity is derived from the computed "
     "risk index but an analyst may escalate with written justification."),
    ("Evidence handling and chain of custody",
     "All incident evidence must be collected in a manner that preserves integrity: capture "
     "volatile memory before disk, hash every artifact at collection time with SHA-256, and "
     "record collector identity and timestamp. Evidence is stored in append-only storage with "
     "access logged. Chain-of-custody records are retained for seven years for any case with "
     "regulatory implications and one year otherwise."),
    ("Breach notification decision tree",
     "Notification obligations begin at the moment of awareness, not the moment of confirmation. "
     "Under GDPR Article 33 a personal-data breach must be reported to the supervisory authority "
     "within 72 hours unless it is unlikely to result in risk to individuals. Where the breach "
     "is likely to result in high risk, affected data subjects must also be notified without "
     "undue delay. Legal counsel makes the final determination; security supplies the facts."),
    ("On-call escalation policy",
     "Tier 1 holds the queue and performs initial triage. Any case reaching risk index 60 "
     "escalates to Tier 2 within 15 minutes. Risk index 80 or any confirmed data exposure "
     "escalates simultaneously to the SOC Manager and the Head of Security Engineering. If the "
     "primary on-call does not acknowledge within 10 minutes, the page routes to secondary."),
    ("Containment authorisation matrix",
     "Analysts may unilaterally block external IP addresses, isolate non-production endpoints "
     "and revoke user sessions. Isolation of a production host, disabling a production service "
     "account, or any action with customer-visible impact requires SOC Manager approval. "
     "Emergency containment may proceed without approval when the alternative is active data "
     "loss, with retrospective sign-off within one hour."),
    ("Log retention standard",
     "Authentication logs, firewall logs and EDR telemetry are retained hot for 90 days and "
     "cold for 400 days. Web access logs are retained hot for 30 days and cold for 180 days. "
     "Any log touched by an open investigation is placed under legal hold and exempted from "
     "expiry until the case closes."),
    ("Vulnerability remediation SLA",
     "Critical (CVSS 9.0+) internet-facing vulnerabilities are remediated within 72 hours. High "
     "(7.0–8.9) within 14 days. Medium within 30 days. Low within 90 days or accepted with "
     "documented risk sign-off. Exploited-in-the-wild status compresses every tier to 24 hours "
     "regardless of base score."),
    ("Least-privilege and access review",
     "Standing privileged access is prohibited; elevation is granted just-in-time with a "
     "maximum four-hour window and mandatory ticket reference. Access is recertified quarterly "
     "by the resource owner. Orphaned accounts are disabled within 24 hours of the joiner-mover-"
     "leaver signal and deleted after 30 days."),
    ("Secure baseline for internet-facing hosts",
     "Password authentication is disabled on SSH. Only certificate-based authentication with "
     "short-lived certificates is permitted. Management interfaces are never exposed publicly; "
     "access is via bastion only. Every internet-facing host runs the EDR agent with tamper "
     "protection enabled and forwards logs off-host in real time."),
    ("Post-incident review standard",
     "Every P1 and P2 case receives a written post-incident review within five business days. "
     "The review documents timeline, dwell time, detection gap, containment latency, and a "
     "blameless analysis of contributing factors. Every review produces at least one committed "
     "control change with a named owner and a due date tracked to completion."),
    ("Threat intelligence handling",
     "Indicators from external feeds are scored and aged: an indicator with no re-observation "
     "in 90 days is retired from blocking to monitoring. Blocking on reputation alone requires "
     "a confidence score of 80 or above from at least two independent sources. All feed "
     "consumption is cached to respect provider rate limits."),
    ("Data classification standard",
     "Restricted covers customer PII, payment data and credentials. Confidential covers "
     "internal financials, source code and architecture documentation. Internal covers routine "
     "business communication. Public covers approved external material. Restricted data may "
     "never leave approved systems, and any egress of restricted data triggers a P1 case."),
]


# ---------------------------------------------------------------------------
def _rand_ts(rng: random.Random, days_back: int = 14) -> datetime:
    """Timestamps weighted toward business hours, with a nocturnal tail."""
    now = datetime.now(timezone.utc)
    delta_days = rng.random() ** 1.6 * days_back  # recency-weighted
    base = now - timedelta(days=delta_days)
    hour = rng.choices(
        population=list(range(24)),
        weights=[3, 2, 2, 2, 2, 3, 5, 8, 12, 14, 15, 14, 13, 14, 15, 14, 12, 9, 7, 6, 5, 4, 4, 3],
        k=1,
    )[0]
    return base.replace(hour=hour, minute=rng.randrange(60), second=rng.randrange(60),
                        microsecond=0)


def _syslog(ts: datetime, host: str, proc: str, pid: int, msg: str) -> str:
    return f"{ts:%b %d %H:%M:%S} {host} {proc}[{pid}]: {msg}"


def _make_ssh_event(rng: random.Random, ts: datetime, host: str, ip: str, *,
                    hostile: bool) -> dict:
    user = rng.choice(USERNAMES)
    port = rng.randrange(30_000, 65_000)
    pid = rng.randrange(1_000, 60_000)
    if hostile:
        if rng.random() < 0.86:
            msg = f"Failed password for {'invalid user ' if rng.random() < 0.5 else ''}{user} from {ip} port {port} ssh2"
            etype, sev, rule = "auth_failure", Severity.MEDIUM.value, "SIG-AUTH-001"
        else:
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
            etype, sev, rule = "auth_success", Severity.HIGH.value, "SIG-AUTH-010"
    else:
        msg = f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:{rng.getrandbits(60):015x}"
        etype, sev, rule = "auth_success", Severity.INFO.value, None
    return {
        "ts": ts, "source": "sshd", "host": host, "src_ip": ip, "dest_port": 22,
        "protocol": "tcp", "username": user, "event_type": etype, "severity": sev,
        "action": "deny" if etype == "auth_failure" else "allow",
        "matched_rule": rule, "message": msg,
        "raw": _syslog(ts, host, "sshd", pid, msg),
        "geo_country": rng.choice(COUNTRIES) if hostile else "US",
        "bytes_in": rng.randrange(200, 2_000), "bytes_out": rng.randrange(200, 4_000),
    }


def _make_web_event(rng: random.Random, ts: datetime, host: str, ip: str, *,
                    hostile: bool) -> dict:
    if hostile:
        path = rng.choice(WEB_PATHS_HOSTILE)
        status = rng.choice([200, 403, 404, 500, 500, 502])
        ua = rng.choice(USER_AGENTS_HOSTILE)
    else:
        path = rng.choice(WEB_PATHS_BENIGN)
        status = rng.choices([200, 200, 200, 301, 404], weights=[70, 10, 10, 5, 5])[0]
        ua = rng.choice(USER_AGENTS_BENIGN)
    size = rng.randrange(180, 90_000)
    raw = (
        f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" '
        f'{status} {size} "-" "{ua}"'
    )
    etype, sev, rule = "http_request", Severity.INFO.value, None
    lowered = path.lower()
    if "union" in lowered or "'" in lowered:
        etype, sev, rule = "sql_injection", Severity.CRITICAL.value, "SIG-WEB-101"
    elif "../" in lowered or "%2e%2e" in lowered:
        etype, sev, rule = "path_traversal", Severity.HIGH.value, "SIG-WEB-102"
    elif "<script" in lowered:
        etype, sev, rule = "xss_attempt", Severity.MEDIUM.value, "SIG-WEB-103"
    elif "cmd.jsp" in lowered:
        etype, sev, rule = "web_shell", Severity.CRITICAL.value, "SIG-WEB-201"
    elif status >= 500:
        sev = Severity.HIGH.value
    elif status == 404 and hostile:
        etype, sev, rule = "recon", Severity.LOW.value, "SIG-RECON-001"
    return {
        "ts": ts, "source": "nginx", "host": host, "src_ip": ip, "dest_port": 443,
        "protocol": "https", "username": None, "event_type": etype, "severity": sev,
        "action": "allow" if status < 400 else "deny", "status_code": status,
        "matched_rule": rule, "user_agent": ua[:255],
        "message": f"GET {path[:120]} → {status}", "raw": raw,
        "geo_country": rng.choice(COUNTRIES) if hostile else "US",
        "bytes_out": size, "bytes_in": rng.randrange(120, 900),
    }


def _make_firewall_event(rng: random.Random, ts: datetime, host: str, ip: str, *,
                         hostile: bool) -> dict:
    dst = rng.choice(INTERNAL_IPS)
    port = rng.choice([22, 445, 3389, 3306, 5432, 8080, 23, 1433] if hostile else [443, 80, 53])
    action = "deny" if hostile else "allow"
    sent = rng.randrange(500_000, 400_000_000) if (not hostile and rng.random() < 0.04) else rng.randrange(200, 60_000)
    raw = (
        f'date={ts:%Y-%m-%d} time={ts:%H:%M:%S} devname="vpn-gw-01" type="traffic" '
        f'action="{action}" srcip={ip} dstip={dst} dstport={port} proto="tcp" '
        f'sentbyte={sent} rcvdbyte={rng.randrange(200, 20_000)} '
        f'user="{rng.choice(USERNAMES)}" service="{"SSH" if port == 22 else "TCP"}"'
    )
    etype = "port_scan" if hostile and rng.random() < 0.5 else ("policy_block" if hostile else "network_flow")
    return {
        "ts": ts, "source": "firewall", "host": host, "src_ip": ip, "dest_ip": dst,
        "dest_port": port, "protocol": "tcp", "event_type": etype,
        "severity": Severity.MEDIUM.value if hostile else Severity.INFO.value,
        "action": action, "matched_rule": "SIG-RECON-001" if etype == "port_scan" else None,
        "message": f"{action} {ip} → {dst}:{port}", "raw": raw,
        "geo_country": rng.choice(COUNTRIES) if hostile else "US",
        "bytes_out": sent, "bytes_in": rng.randrange(200, 20_000),
    }


def _make_winauth_event(rng: random.Random, ts: datetime, host: str, ip: str, *,
                        hostile: bool) -> dict:
    user = rng.choice(USERNAMES)
    if hostile:
        eid, etype, sev = 4625, "auth_failure", Severity.MEDIUM.value
        msg = f"An account failed to log on. Account: {user} Source: {ip} Logon type: 3 Status: 0xC000006D"
    else:
        eid, etype, sev = 4624, "auth_success", Severity.INFO.value
        msg = f"An account was successfully logged on. Account: {user} Source: {ip} Logon type: 2"
    raw = (
        f'EventID={eid} TimeCreated="{ts:%Y-%m-%dT%H:%M:%SZ}" Computer="{host}" '
        f'TargetUserName="{user}" IpAddress={ip} LogonType={3 if hostile else 2} '
        f'Channel="Security"'
    )
    return {
        "ts": ts, "source": "winauth", "host": host, "src_ip": ip, "protocol": "smb",
        "dest_port": 445, "username": user, "event_type": etype, "severity": sev,
        "action": "deny" if hostile else "allow",
        "matched_rule": "SIG-AUTH-001" if hostile else None,
        "message": msg, "raw": raw, "geo_country": "US",
        "bytes_in": rng.randrange(200, 3_000), "bytes_out": rng.randrange(200, 3_000),
    }


GENERATORS = {
    "sshd": _make_ssh_event, "nginx": _make_web_event,
    "firewall": _make_firewall_event, "winauth": _make_winauth_event,
}


def _generator_for(source: str):
    return GENERATORS.get(source, _make_firewall_event)


# ---------------------------------------------------------------------------
def _seed_users(db: Session) -> list[User]:
    users = []
    for spec in DEMO_USERS:
        user = User(
            email=spec["email"], full_name=spec["full_name"], role=spec["role"],
            job_title=spec["job_title"], team=spec["team"],
            hashed_password=hash_password(spec["password"]),
            is_active=True, auth_provider="local", mfa_enrolled=True,
            last_login_at=datetime.now(timezone.utc) - timedelta(hours=len(users) * 5 + 2),
        )
        db.add(user)
        users.append(user)
    db.flush()
    log.info("Seeded %d users", len(users))
    return users


def _seed_knowledge(db: Session, rng: random.Random, target: int) -> int:
    docs: list[KnowledgeDoc] = []

    for tech in mitre.TECHNIQUES:
        docs.append(
            KnowledgeDoc(
                doc_key=f"mitre-{tech['id'].lower().replace('.', '-')}",
                title=f"{tech['id']} — {tech['name']}",
                category="mitre", source="MITRE ATT&CK v15",
                technique_id=tech["id"], tactic=tech["tactic"],
                tags=[tech["tactic"].lower().replace(" ", "-"), "attack"],
                content=(
                    f"Technique {tech['id']} ({tech['name']}) belongs to the {tech['tactic']} "
                    f"tactic.\n\nDescription: {tech['description']}\n\n"
                    f"Detection guidance: {tech['detection']}\n\n"
                    f"Mitigation: {tech['mitigation']}\n\n"
                    f"Common log indicators: {', '.join(tech['keywords'])}."
                ),
            )
        )

    for key, pb in playbooks.PLAYBOOKS.items():
        docs.append(
            KnowledgeDoc(
                doc_key=f"playbook-{key}", title=f"Playbook — {pb['name']}",
                category="playbook", source="SentinelAI Response Library",
                tactic=None, tags=pb["applies_to"] + ["playbook", "nist-800-61"],
                content=(
                    f"{pb['name']}\nApplies to: {', '.join(pb['applies_to'])}\n"
                    f"Containment SLA: {pb['sla_minutes']} minutes.\n\n"
                    + "\n".join(
                        f"[{phase}] {title}: {detail}"
                        for phase, title, detail, _ in pb["steps"]
                    )
                ),
            )
        )
        for position, (phase, title, detail, automatable) in enumerate(pb["steps"]):
            docs.append(
                KnowledgeDoc(
                    doc_key=f"step-{key}-{position}",
                    title=f"{pb['name']} · {title}",
                    category="playbook", source="SentinelAI Response Library",
                    tags=[phase, *pb["applies_to"]],
                    content=(
                        f"Phase: {phase}. Action: {title}.\n{detail}\n"
                        f"Automation: {'available via SOAR' if automatable else 'manual step'}.\n"
                        f"Part of the {pb['name']} playbook."
                    ),
                )
            )

    for cve_id, title, cvss, description in CVES:
        docs.append(
            KnowledgeDoc(
                doc_key=f"cve-{cve_id.lower()}", title=f"{cve_id} — {title}",
                category="cve", source="NVD",
                severity="critical" if cvss >= 9 else "high" if cvss >= 7 else "medium",
                tags=["cve", "vulnerability"],
                content=(
                    f"{cve_id}: {title}. CVSS v3.1 base score {cvss}.\n\n{description}\n\n"
                    f"Remediation: apply the vendor patch within the SLA tier for a "
                    f"{cvss} base score. Where patching is delayed, apply compensating "
                    f"controls: restrict network reachability, enable virtual patching at the "
                    f"WAF or IPS, and increase monitoring on affected assets."
                ),
            )
        )

    for title, body in POLICY_DOCS:
        docs.append(
            KnowledgeDoc(
                doc_key=f"policy-{title.lower().replace(' ', '-')[:48]}",
                title=f"Policy — {title}", category="policy",
                source="SentinelAI Security Policy Set",
                tags=["policy", "governance"], content=f"{title}\n\n{body}",
            )
        )

    # Detection-engineering notes fill out the corpus to the configured target.
    detection_topics = [
        ("Detecting credential stuffing at the edge",
         "Credential stuffing differs from brute force in that each attempt uses a distinct "
         "username/password pair harvested from an unrelated breach. The volumetric signal is "
         "weaker; the discriminating features are user-agent uniformity, the absence of prior "
         "session cookies, and an implausibly high distinct-username rate per source ASN."),
        ("Beacon detection without TLS inspection",
         "Where TLS inspection is not lawful or feasible, beacons remain detectable through "
         "metadata: connection interval regularity (low jitter), consistent request and "
         "response sizes, long-lived sessions to rare destinations, and JA3/JA3S fingerprints "
         "that do not match any installed browser."),
        ("Baselining egress for exfiltration detection",
         "Build a per-host, per-hour egress baseline over 30 days and alert on multi-sigma "
         "deviation rather than a static threshold. Static thresholds either miss slow "
         "exfiltration from low-volume hosts or drown the queue in false positives from "
         "backup jobs."),
        ("Reducing false positives in authentication alerting",
         "The dominant false-positive source in authentication alerting is service accounts "
         "with stale credentials retrying in a loop. Maintain an allow-list keyed on account "
         "plus source, and route those to a suppression queue with a weekly review rather than "
         "dropping them silently."),
        ("Windows event IDs worth alerting on",
         "4625 (failed logon), 4672 (special privileges assigned), 4720 (account created), "
         "4732 (member added to security-enabled local group), 1102 (audit log cleared), "
         "7045 (service installed), and 4698 (scheduled task created) carry the highest "
         "signal-to-noise ratio for intrusion detection."),
        ("Linux auditd rules for intrusion detection",
         "Watch execve of interpreters by service accounts, writes to /etc/passwd, "
         "/etc/shadow, /etc/sudoers and ~/.ssh/authorized_keys, module loading, and any "
         "process that unlinks files under /var/log. Forward auditd off-host in real time."),
        ("Kubernetes attack surface monitoring",
         "Alert on exec into a running pod, creation of privileged containers, service-account "
         "token mounting in namespaces that do not require it, and any anonymous request that "
         "reaches the API server. Audit-log every RBAC binding change."),
        ("Cloud identity threat detection",
         "Console logins without MFA, access-key creation on an account that has never used "
         "one, cross-region API calls from a workload pinned to a single region, and any use "
         "of the root account are the highest-value cloud identity signals."),
        ("DNS telemetry for early-stage detection",
         "DNS is often the first place a new compromise becomes visible. Alert on newly "
         "registered domains, algorithmically generated names by entropy score, subdomain "
         "lengths above the 99th percentile, and NXDOMAIN rates that spike per client."),
        ("Email as an initial access vector",
         "Join mail-gateway verdicts to proxy first-click telemetry. The window between "
         "delivery and click is the only period in which takedown is cheap. Automate retraction "
         "of messages whose verdict flips after delivery."),
        ("Measuring detection coverage against ATT&CK",
         "Coverage should be measured as the fraction of techniques with at least one "
         "validated detection that has fired at least once in the last 90 days, not the "
         "fraction with a rule written. Rules that never fire are usually broken."),
        ("Purple-team validation cadence",
         "Every detection should be exercised at least quarterly by an atomic test that "
         "reproduces the technique in a controlled way. A detection that has not been "
         "validated since it was written is a hypothesis, not a control."),
    ]
    for title, body in detection_topics:
        docs.append(
            KnowledgeDoc(
                doc_key=f"detect-{title.lower().replace(' ', '-')[:48]}",
                title=f"Detection note — {title}", category="detection",
                source="SentinelAI Detection Engineering",
                tags=["detection", "engineering"], content=f"{title}\n\n{body}",
            )
        )

    # Pad with per-tactic overview docs if we are still short of the target.
    idx = 0
    tactic_names = list(mitre.TACTICS.values())
    while len(docs) < target:
        tactic = tactic_names[idx % len(tactic_names)]
        related = [t for t in mitre.TECHNIQUES if t["tactic"] == tactic]
        docs.append(
            KnowledgeDoc(
                doc_key=f"tactic-{tactic.lower().replace(' ', '-')}-{idx}",
                title=f"Tactic overview — {tactic}",
                category="mitre", source="MITRE ATT&CK v15", tactic=tactic,
                tags=["tactic", tactic.lower().replace(" ", "-")],
                content=(
                    f"The {tactic} tactic describes the adversary objective at this stage of "
                    f"an intrusion. Techniques observed in this environment mapped to "
                    f"{tactic}: "
                    + (", ".join(f"{t['id']} {t['name']}" for t in related) or "none currently mapped")
                    + ". Detection strategy should combine at least one signature-based control "
                    "with one behavioural control, since signature coverage alone leaves "
                    "novel variants undetected."
                ),
            )
        )
        idx += 1

    db.add_all(docs)
    db.flush()
    log.info("Seeded %d knowledge documents", len(docs))
    return len(docs)


def _seed_compliance(db: Session, rng: random.Random) -> int:
    rows = []
    for framework, source in (("ISO27001", ISO_CONTROLS), ("SOC2", SOC2_CONTROLS)):
        for control_id, domain, title in source:
            roll = rng.random()
            if roll < 0.66:
                status, score = "compliant", rng.randrange(92, 101)
                gap = ""
                evidence = (
                    f"Control operating effectively. Last evidence sample collected "
                    f"{rng.randrange(2, 40)} days ago; no exceptions noted."
                )
            elif roll < 0.87:
                status, score = "partial", rng.randrange(48, 78)
                gap = rng.choice([
                    "Control is implemented for production but not yet extended to the staging estate.",
                    "Evidence collection is manual; automation is scheduled for next quarter.",
                    "Coverage confirmed for cloud workloads only; on-premise remains out of scope.",
                    "Policy exists and is approved, but operational adherence is not yet measured.",
                ])
                evidence = "Partial evidence available; remediation plan has a named owner and due date."
            elif roll < 0.95:
                status, score = "gap", rng.randrange(0, 35)
                gap = rng.choice([
                    "No implemented control identified. Raised as a finding with the control owner.",
                    "Control was decommissioned during the platform migration and not reinstated.",
                    "Tooling is procured but not deployed; no operational coverage today.",
                ])
                evidence = "No sufficient evidence of operation during the review period."
            else:
                status, score = "na", 0
                gap = ""
                evidence = "Not applicable to the current scope statement; exclusion documented."

            rows.append(
                ComplianceControl(
                    framework=framework, control_id=control_id, domain=domain, title=title,
                    description=(
                        f"{framework} {control_id} — {title}. Assessed against the current "
                        f"scope statement covering production infrastructure, the SentinelAI "
                        f"platform itself, and all systems processing customer data."
                    ),
                    status=status, score=score, gap_notes=gap, evidence=evidence,
                    owner=rng.choice([
                        "Security Engineering", "Security Operations", "Platform Engineering",
                        "Governance, Risk & Compliance", "IT Operations",
                    ]),
                    last_reviewed=datetime.now(timezone.utc) - timedelta(days=rng.randrange(1, 120)),
                )
            )
    db.add_all(rows)
    db.flush()
    log.info("Seeded %d compliance controls", len(rows))
    return len(rows)


def _seed_incidents_and_events(
    db: Session, rng: random.Random, users: list[User], n_incidents: int, n_events: int
) -> tuple[int, int]:
    analysts = [u for u in users if u.role in {Role.ANALYST.value, Role.MANAGER.value}]
    incidents: list[Incident] = []
    events_created = 0

    statuses = (
        [IncidentStatus.NEW.value] * 5
        + [IncidentStatus.TRIAGING.value] * 4
        + [IncidentStatus.INVESTIGATING.value] * 4
        + [IncidentStatus.CONTAINED.value] * 3
        + [IncidentStatus.REMEDIATED.value] * 2
        + [IncidentStatus.CLOSED.value] * 4
        + [IncidentStatus.FALSE_POSITIVE.value] * 2
    )

    for i in range(n_incidents):
        template = INCIDENT_TEMPLATES[i % len(INCIDENT_TEMPLATES)]
        host, source, criticality = rng.choice(HOSTS)
        hostile_ip = rng.choice(HOSTILE_IPS)
        internal_ip = rng.choice(INTERNAL_IPS)
        origin = internal_ip if template["category"] in {
            "lateral-movement", "privilege-escalation", "persistence"
        } else hostile_ip
        created = _rand_ts(rng, days_back=13)
        count = rng.randrange(6, 42)
        user = rng.choice(USERNAMES)

        fmt = {"asset": host, "ip": origin, "count": count, "user": user}
        status = statuses[i % len(statuses)]
        severity = rng.choices(
            [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value],
            weights=[12, 30, 40, 18],
        )[0]
        risk = {"critical": rng.randrange(80, 99), "high": rng.randrange(60, 80),
                "medium": rng.randrange(35, 60), "low": rng.randrange(10, 35)}[severity]

        incident = Incident(
            ref=f"INC-{created:%Y}-{i + 1001}",
            title=template["title"].format(**fmt),
            summary=template["summary"].format(**fmt),
            severity=severity, status=status,
            priority={"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}[severity],
            risk_score=risk, confidence=rng.randrange(58, 95),
            category=template["category"], detection_source=template["detection"],
            asset=host, asset_criticality=criticality,
            src_ip=origin, dest_ip=internal_ip, affected_user=user,
            mitre_techniques=mitre.CATEGORY_TECHNIQUES.get(template["category"], [])[:3],
            kill_chain_phase=rng.choice([
                "reconnaissance", "initial-access", "execution", "persistence",
                "privilege-escalation", "lateral-movement", "exfiltration",
            ]),
            tags=template["tags"],
            assignee_id=(rng.choice(analysts).id if analysts and rng.random() < 0.72 else None),
            created_at=created,
            updated_at=created + timedelta(minutes=rng.randrange(5, 900)),
            sla_due_at=created + timedelta(minutes=rng.choice([15, 30, 60, 240, 480])),
            closed_at=(
                created + timedelta(hours=rng.randrange(2, 60))
                if status in {IncidentStatus.CLOSED.value, IncidentStatus.FALSE_POSITIVE.value}
                else None
            ),
        )
        db.add(incident)
        db.flush()
        incidents.append(incident)

        # Correlated evidence cluster
        generator = _generator_for(source if source in GENERATORS else "firewall")
        cluster = rng.randrange(5, 22)
        for k in range(cluster):
            ts = created + timedelta(seconds=k * rng.randrange(2, 45))
            payload = generator(rng, ts, host, origin, hostile=True)
            payload["incident_id"] = incident.id
            db.add(SecurityEvent(**payload))
            events_created += 1

        # Playbook checklist
        key, pb = playbooks.for_category(incident.category)
        incident.playbook_key = key
        completed_through = {
            IncidentStatus.NEW.value: 0, IncidentStatus.TRIAGING.value: 1,
            IncidentStatus.INVESTIGATING.value: 2, IncidentStatus.CONTAINED.value: 4,
            IncidentStatus.REMEDIATED.value: 6, IncidentStatus.CLOSED.value: len(pb["steps"]),
            IncidentStatus.FALSE_POSITIVE.value: 1,
        }.get(status, 0)
        for position, (phase, title, detail, automatable) in enumerate(pb["steps"]):
            done = position < completed_through
            db.add(
                PlaybookItem(
                    incident_id=incident.id, position=position, phase=phase, title=title,
                    detail=detail, automatable=automatable, completed=done,
                    completed_by_id=(rng.choice(analysts).id if done and analysts else None),
                    completed_at=(created + timedelta(minutes=15 * (position + 1))) if done else None,
                )
            )

        # Analyst notes
        for note_body, kind in _notes_for(rng, incident, status):
            db.add(
                IncidentNote(
                    incident_id=incident.id,
                    author_id=(rng.choice(analysts).id if analysts else None),
                    body=note_body, kind=kind,
                    created_at=created + timedelta(minutes=rng.randrange(3, 400)),
                )
            )

    # Background telemetry (uncorrelated). A floor is enforced independently of
    # the incident clusters: the anomaly detector trains on *nominal* traffic,
    # and if every seeded event belonged to an incident there would be no
    # baseline to learn from.
    remaining = max(n_events - events_created, 320)
    for _ in range(remaining):
        host, source, _crit = rng.choice(HOSTS)
        hostile = rng.random() < 0.17
        ip = rng.choice(HOSTILE_IPS if hostile else (BENIGN_IPS + INTERNAL_IPS))
        generator = _generator_for(source if source in GENERATORS else "firewall")
        db.add(SecurityEvent(**generator(rng, _rand_ts(rng), host, ip, hostile=hostile)))
        events_created += 1

    db.flush()
    log.info("Seeded %d incidents and %d events", len(incidents), events_created)
    return len(incidents), events_created


def _notes_for(rng: random.Random, incident: Incident, status: str) -> list[tuple[str, str]]:
    notes: list[tuple[str, str]] = [(
        f"Picked this up from the queue. Confirming whether {incident.src_ip} maps to any known "
        f"automation before treating it as hostile.", "note",
    )]
    if status in {
        IncidentStatus.INVESTIGATING.value, IncidentStatus.CONTAINED.value,
        IncidentStatus.REMEDIATED.value, IncidentStatus.CLOSED.value,
    }:
        notes.append((
            f"Reviewed the correlated telemetry on {incident.asset}. "
            + rng.choice([
                "The cadence is too regular for a human operator — this is tooling.",
                "Nothing in the change calendar accounts for this activity window.",
                "Asset owner confirms no maintenance was scheduled. Treating as hostile.",
                "Cross-referenced against the CMDB; the account involved should not have this access.",
            ]), "note",
        ))
    if status in {IncidentStatus.CONTAINED.value, IncidentStatus.REMEDIATED.value,
                  IncidentStatus.CLOSED.value}:
        notes.append((
            f"Containment actions applied: source blocked at the perimeter, sessions revoked on "
            f"{incident.asset}. Monitoring for re-attempts from adjacent ranges.", "status",
        ))
    if status == IncidentStatus.CLOSED.value:
        notes.append((
            "Post-incident review complete. Control change committed: "
            + rng.choice([
                "password authentication disabled on the exposed service.",
                "WAF rule promoted from monitor to block mode.",
                "egress DLP rule enabled for this data classification.",
                "east-west segmentation policy tightened for this host group.",
            ]), "status",
        ))
    if status == IncidentStatus.FALSE_POSITIVE.value:
        notes.append((
            "Confirmed benign — the traffic originates from the vulnerability scanner "
            "commissioned by the platform team. Detection tuned to exclude the scanner's "
            "source range with a documented exception.", "status",
        ))
    return notes


def _seed_saved_hunts(db: Session, users: list[User]) -> None:
    owner = next((u for u in users if u.role == Role.ANALYST.value), users[0] if users else None)
    presets = [
        ("Failed root logins", "event_type:auth_failure user:root"),
        ("Critical severity, last sweep", "severity:critical"),
        ("Server errors on the web tier", "status>=500 source:nginx"),
        ("SQL injection payloads", '"union select"'),
        ("Bulletproof hosting ranges", "src_ip:45.* OR src_ip:185.*"),
        ("Non-informational database activity", "host:db-prod-01 -severity:info"),
    ]
    for name, query in presets:
        db.add(SavedHunt(name=name, query=query,
                         owner_id=getattr(owner, "id", None), shared=True))
    db.flush()


def _run_investigations(db: Session, count: int) -> int:
    """Execute the real agent pipeline so seeded timelines are genuine output."""
    from .services.agent_pipeline import run_pipeline

    incidents = db.execute(
        select(Incident).order_by(Incident.risk_score.desc()).limit(count)
    ).scalars().all()
    done = 0
    for incident in incidents:
        try:
            run_pipeline(db, incident, reason="auto-triage", apply_to_incident=True)
            done += 1
        except Exception:
            log.exception("Seed investigation failed for %s", incident.ref)
    db.flush()
    log.info("Seeded %d agent investigations", done)
    return done


# ---------------------------------------------------------------------------
def database_is_empty(db: Session) -> bool:
    return db.execute(select(func.count()).select_from(User)).scalar_one() == 0


def seed_if_empty(force: bool = False) -> dict:
    """Entry point called on startup. Safe to call repeatedly."""
    with session_scope() as db:
        if not force and not database_is_empty(db):
            return {"seeded": False, "reason": "database already populated"}

        rng = random.Random(settings.seed_random_state)
        log.info("Seeding SentinelAI database …")

        users = _seed_users(db)
        docs = _seed_knowledge(db, rng, settings.seed_documents)
        controls = _seed_compliance(db, rng)
        incidents, events = _seed_incidents_and_events(
            db, rng, users, settings.seed_incidents, settings.seed_events
        )
        _seed_saved_hunts(db, users)

    # RAG index must exist before investigations run, so agents can cite sources.
    from .services.rag import rebuild_from_db

    rag_stats = rebuild_from_db()

    with session_scope() as db:
        investigations = _run_investigations(db, settings.seed_investigations)

    summary = {
        "seeded": True,
        "users": len(users),
        "knowledge_documents": docs,
        "compliance_controls": controls,
        "incidents": incidents,
        "security_events": events,
        "investigations": investigations,
        "rag": rag_stats,
    }
    log.info("Seed complete: %s", summary)
    return summary
