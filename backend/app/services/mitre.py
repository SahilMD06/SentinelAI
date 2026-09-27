"""MITRE ATT&CK reference subset used for mapping, RAG corpus and UI labels.

Deliberately a curated subset covering the techniques a mid-size SOC actually
sees week to week, each with the detection and mitigation prose the agents
quote back into incident timelines.
"""

from __future__ import annotations

TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TECHNIQUES: list[dict] = [
    {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "keywords": ["failed password", "authentication failure", "invalid user", "login attempt"],
        "description": (
            "Adversaries systematically guess credentials when they lack a valid password. "
            "High-volume authentication failures from a single source against many accounts, "
            "or against one account across many sources, are the canonical signal."
        ),
        "detection": (
            "Alert on >20 authentication failures from one source IP inside 5 minutes, and on "
            "any failure burst followed within 60s by a success from the same source."
        ),
        "mitigation": (
            "Enforce account lockout thresholds, deploy MFA on all externally reachable "
            "authentication surfaces, rate-limit at the edge, and disable password auth for SSH "
            "in favour of certificate-based keys."
        ),
    },
    {
        "id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access",
        "keywords": ["password spray", "many users", "single password"],
        "description": (
            "A low-and-slow variant: one or two common passwords tried against a large user "
            "population, staying beneath per-account lockout thresholds."
        ),
        "detection": "Correlate on distinct-username count per source IP rather than failure count per account.",
        "mitigation": "Ban common passwords, apply smart lockout, and monitor tenant-wide failure ratios.",
    },
    {
        "id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion",
        "keywords": ["successful login", "impossible travel", "unusual hours", "legitimate credentials"],
        "description": (
            "Use of compromised legitimate credentials, which blends with normal activity and "
            "evades signature detection entirely."
        ),
        "detection": "Baseline per-user login geography, hour-of-day, and device; alert on deviation.",
        "mitigation": "Conditional access policies, session risk scoring, and just-in-time privilege elevation.",
    },
    {
        "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
        "keywords": ["sql injection", "union select", "path traversal", "../", "rce", "deserialization"],
        "description": (
            "Exploitation of an internet-facing service, most often a web application, to gain "
            "an initial foothold inside the perimeter."
        ),
        "detection": "WAF signature hits, 500-class responses on unusual paths, and anomalous URI entropy.",
        "mitigation": "Virtual patching at the WAF, dependency SCA in CI, and network segmentation of the DMZ.",
    },
    {
        "id": "T1505.003", "name": "Web Shell", "tactic": "Persistence",
        "keywords": ["web shell", "cmd.jsp", "eval(", "base64_decode", "uploads/"],
        "description": (
            "A script planted in a web-accessible directory that grants the operator persistent "
            "command execution as the web server user."
        ),
        "detection": "File-integrity monitoring on web roots plus outbound connections initiated by the web user.",
        "mitigation": "Read-only web roots, disable script execution in upload directories, egress filtering.",
    },
    {
        "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
        "keywords": ["/bin/sh", "powershell", "-enc", "bash -i", "cmd.exe"],
        "description": "Abuse of native interpreters to execute payloads without dropping binaries.",
        "detection": "Process-lineage alerting: interpreter spawned by a service account or web process.",
        "mitigation": "Constrained language mode, script-block logging, and application allow-listing.",
    },
    {
        "id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
        "keywords": ["privilege escalation", "kernel exploit", "setuid", "sudo"],
        "description": "Exploiting a software flaw to move from user to elevated or root context.",
        "detection": "Unexpected uid transitions and setuid binary execution outside change windows.",
        "mitigation": "Aggressive kernel patch SLAs, least-privilege service accounts, and seccomp profiles.",
    },
    {
        "id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
        "keywords": ["sudo", "setuid", "uac bypass", "pkexec"],
        "description": "Misuse of legitimate elevation mechanisms to obtain higher privileges.",
        "detection": "Audit sudoers changes and monitor pkexec/polkit invocations by non-admin users.",
        "mitigation": "Restrict sudoers with explicit command allow-lists; require re-authentication.",
    },
    {
        "id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement",
        "keywords": ["ssh", "accepted publickey", "port 22", "lateral"],
        "description": "Movement between hosts over SSH using harvested keys or credentials.",
        "detection": "East-west SSH sessions that violate the expected host-to-host connectivity matrix.",
        "mitigation": "Bastion-only access, short-lived certificates, and micro-segmentation.",
    },
    {
        "id": "T1071.001", "name": "Application Layer Protocol: Web", "tactic": "Command and Control",
        "keywords": ["beacon", "c2", "https callback", "periodic request"],
        "description": "C2 traffic hidden inside ordinary HTTP/S so it blends with browsing traffic.",
        "detection": "Beacon analysis: low jitter, consistent payload sizes, rare-destination scoring.",
        "mitigation": "TLS inspection where lawful, DNS/HTTP egress proxying, and destination reputation blocking.",
    },
    {
        "id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control",
        "keywords": ["dns tunnel", "txt record", "long subdomain", "nxdomain"],
        "description": "Encoding C2 or exfiltration data inside DNS queries and responses.",
        "detection": "Alert on high-entropy subdomains, oversized TXT responses, and NXDOMAIN bursts.",
        "mitigation": "Force all resolution through inspected internal resolvers; block direct outbound 53.",
    },
    {
        "id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
        "keywords": ["large upload", "bytes_out", "data transfer", "exfil"],
        "description": "Stolen data leaves over the same channel already used for command and control.",
        "detection": "Per-host egress volume baselines with alerting on multi-sigma deviation.",
        "mitigation": "DLP at the egress boundary, rate limiting, and data-tier access review.",
    },
    {
        "id": "T1567.002", "name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration",
        "keywords": ["s3", "dropbox", "mega.nz", "cloud upload"],
        "description": "Transfer of collected data to attacker-controlled cloud storage services.",
        "detection": "Egress to unsanctioned storage domains, especially from server subnets.",
        "mitigation": "CASB enforcement and an explicit allow-list of sanctioned storage tenants.",
    },
    {
        "id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
        "keywords": ["ransomware", "encrypt", "shadow copy", "vssadmin", ".locked"],
        "description": "Mass encryption of files to interrupt operations and extort payment.",
        "detection": "Rapid file-rename entropy spikes and shadow-copy deletion commands.",
        "mitigation": "Immutable offline backups, canary file shares, and EDR rollback capability.",
    },
    {
        "id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact",
        "keywords": ["vssadmin delete", "wbadmin", "bcdedit", "backup deleted"],
        "description": "Destruction of backups and recovery points immediately before encryption.",
        "detection": "Any invocation of vssadmin/wbadmin delete outside a maintenance window.",
        "mitigation": "Backup accounts isolated from the production domain; write-once retention.",
    },
    {
        "id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access",
        "keywords": ["lsass", "mimikatz", "/etc/shadow", "sam hive"],
        "description": "Extraction of credential material from OS memory or on-disk stores.",
        "detection": "Handle-open events against LSASS and reads of shadow/SAM by non-system processes.",
        "mitigation": "Credential Guard, LSA protection, and restricted local-admin group membership.",
    },
    {
        "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
        "keywords": ["port scan", "nmap", "syn scan", "connection refused"],
        "description": "Enumeration of reachable services to plan the next stage of the intrusion.",
        "detection": "One source touching many distinct ports/hosts inside a short window.",
        "mitigation": "Default-deny east-west policy and honeypot ports that alert on first touch.",
    },
    {
        "id": "T1087", "name": "Account Discovery", "tactic": "Discovery",
        "keywords": ["net user", "ldapsearch", "enumerate accounts", "getent passwd"],
        "description": "Enumeration of user and group accounts to select escalation targets.",
        "detection": "Bulk LDAP queries from non-directory service accounts.",
        "mitigation": "LDAP query rate limits and removal of anonymous bind.",
    },
    {
        "id": "T1562.001", "name": "Impair Defenses: Disable Tools", "tactic": "Defense Evasion",
        "keywords": ["stop service", "disable defender", "auditd", "kill agent"],
        "description": "Disabling or tampering with security agents and logging to avoid detection.",
        "detection": "Agent heartbeat loss correlated with a preceding process-stop event.",
        "mitigation": "Tamper protection, out-of-band heartbeat monitoring, and immutable audit forwarding.",
    },
    {
        "id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion",
        "keywords": ["clear log", "history -c", "wevtutil cl", "truncate"],
        "description": "Deletion or truncation of logs and artifacts to frustrate investigation.",
        "detection": "Log-clearing event IDs and unexpected gaps in forwarded log continuity.",
        "mitigation": "Ship logs off-host in real time to append-only storage.",
    },
    {
        "id": "T1136", "name": "Create Account", "tactic": "Persistence",
        "keywords": ["useradd", "new user created", "net user /add"],
        "description": "Creation of a new account to retain access independent of the original vector.",
        "detection": "Any account creation outside the IAM provisioning pipeline.",
        "mitigation": "Break-glass-only local account creation with mandatory ticket correlation.",
    },
    {
        "id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence",
        "keywords": ["crontab", "schtasks", "systemd timer", "at job"],
        "description": "Scheduled execution used to survive reboots and re-establish access.",
        "detection": "Diff scheduled-task inventories per host against a known-good baseline.",
        "mitigation": "Configuration management ownership of all scheduled jobs.",
    },
    {
        "id": "T1098", "name": "Account Manipulation", "tactic": "Persistence",
        "keywords": ["authorized_keys", "group added", "password changed", "role granted"],
        "description": "Modification of accounts, keys or roles to maintain and broaden access.",
        "detection": "Monitor authorized_keys writes and privileged group membership deltas.",
        "mitigation": "Immutable key distribution and mandatory approval for privileged role grants.",
    },
    {
        "id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
        "keywords": ["scanner", "user-agent nmap", "probe", "404 sweep"],
        "description": "Pre-attack probing of the external attack surface for exploitable services.",
        "detection": "Edge 404/403 sweep detection and known-scanner user-agent matching.",
        "mitigation": "Attack-surface reduction and edge rate limiting with reputation blocking.",
    },
    {
        "id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact",
        "keywords": ["flood", "resource exhaustion", "503", "connection saturation"],
        "description": "Resource exhaustion that degrades or removes availability of a service.",
        "detection": "Sustained request-rate and error-rate breach on edge telemetry.",
        "mitigation": "CDN absorption, adaptive rate limiting, and autoscaling guardrails.",
    },
    {
        "id": "T1552.001", "name": "Unsecured Credentials: Files", "tactic": "Credential Access",
        "keywords": [".env", "credentials file", "id_rsa", "hardcoded password"],
        "description": "Harvesting secrets left in configuration files, source or history.",
        "detection": "Reads of .env/id_rsa by unexpected processes; secret-scanning in CI.",
        "mitigation": "Central secret manager with short-lived dynamic credentials.",
    },
    {
        "id": "T1566", "name": "Phishing", "tactic": "Initial Access",
        "keywords": ["phish", "malicious attachment", "credential harvest page"],
        "description": "Socially engineered messages delivering malware or harvesting credentials.",
        "detection": "Mail gateway verdicts joined with first-click telemetry from the proxy.",
        "mitigation": "MFA everywhere, attachment detonation, and rapid click-through takedown.",
    },
    {
        "id": "T1204", "name": "User Execution", "tactic": "Execution",
        "keywords": ["macro enabled", "user opened", "double click"],
        "description": "Reliance on a user to run the payload that establishes the foothold.",
        "detection": "Office/PDF reader spawning interpreters or network utilities.",
        "mitigation": "Block macros from the internet; enforce protected view.",
    },
    {
        "id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
        "keywords": ["base64", "-enc", "packed", "xor"],
        "description": "Encoding or packing payloads to defeat static inspection.",
        "detection": "Entropy scoring of command lines and script bodies.",
        "mitigation": "AMSI/script-block logging with inline content inspection.",
    },
    {
        "id": "T1219", "name": "Remote Access Software", "tactic": "Command and Control",
        "keywords": ["anydesk", "teamviewer", "screenconnect", "rmm"],
        "description": "Abuse of legitimate remote-access tooling for persistent operator access.",
        "detection": "Inventory-based detection of unsanctioned RMM binaries and their domains.",
        "mitigation": "Allow-list a single sanctioned RMM; block the rest at DNS and endpoint.",
    },
]

BY_ID: dict[str, dict] = {t["id"]: t for t in TECHNIQUES}


def technique(tid: str) -> dict | None:
    return BY_ID.get(tid)


def label(tid: str) -> str:
    t = BY_ID.get(tid)
    return f"{tid} · {t['name']}" if t else tid


def match_text(text: str, limit: int = 4) -> list[dict]:
    """Keyword-driven ATT&CK mapping used by the mapper agent."""
    lowered = text.lower()
    scored: list[tuple[int, dict]] = []
    for tech in TECHNIQUES:
        hits = sum(1 for kw in tech["keywords"] if kw in lowered)
        if hits:
            scored.append((hits, tech))
    scored.sort(key=lambda pair: -pair[0])
    return [t for _, t in scored[:limit]]


CATEGORY_TECHNIQUES: dict[str, list[str]] = {
    "brute-force": ["T1110", "T1110.003", "T1078"],
    "credential-access": ["T1110.003", "T1003", "T1552.001", "T1078"],
    "web-exploit": ["T1190", "T1505.003", "T1059"],
    "malware": ["T1204", "T1027", "T1059", "T1071.001"],
    "data-exfiltration": ["T1041", "T1567.002", "T1071.004"],
    "ransomware": ["T1486", "T1490", "T1562.001"],
    "privilege-escalation": ["T1068", "T1548", "T1098"],
    "lateral-movement": ["T1021.004", "T1046", "T1087"],
    "reconnaissance": ["T1595", "T1046"],
    "policy-violation": ["T1219", "T1078"],
    "intrusion-attempt": ["T1190", "T1110", "T1595"],
    "availability": ["T1499"],
    "persistence": ["T1053", "T1136", "T1098", "T1505.003"],
    "defense-evasion": ["T1070", "T1562.001", "T1027"],
}
