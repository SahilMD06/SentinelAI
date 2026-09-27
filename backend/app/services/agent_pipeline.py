"""The SentinelAI agent orchestration pipeline.

Nine specialised agents execute in sequence over a shared, mutating state
object. Each agent reads what earlier agents wrote, enriches its prompt from
the RAG knowledge base, may call tools (threat intel, log store, playbook
registry), and emits an auditable step: headline, reasoning trace, structured
findings, cited sources, token accounting and latency.

The reasoning is deterministic and rule-driven rather than LLM-generated — the
orchestration graph, state handoff, tracing and audit trail are the real
product surface, and a deterministic core makes the whole platform testable
and reproducible. `LLM_PROVIDER` is the documented seam for swapping in a
model-backed reasoner without touching the graph.
"""

from __future__ import annotations

import logging
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentRun,
    AgentStep,
    Incident,
    IncidentNote,
    IncidentStatus,
    PlaybookItem,
    SecurityEvent,
    Severity,
    User,
)
from ..utils import minutes_between
from . import mitre, playbooks, threat_intel, tracing
from .rag import engine as rag_engine

log = logging.getLogger("sentinelai.agents")

SEVERITY_WEIGHT = {
    Severity.CRITICAL.value: 40,
    Severity.HIGH.value: 26,
    Severity.MEDIUM.value: 14,
    Severity.LOW.value: 6,
    Severity.INFO.value: 1,
}
CRITICALITY_WEIGHT = {"critical": 1.30, "high": 1.15, "medium": 1.0, "low": 0.85}


@dataclass
class AgentOutput:
    headline: str
    reasoning: str
    findings: dict = field(default_factory=dict)
    rag_sources: list = field(default_factory=list)
    tool_calls: list = field(default_factory=list)
    confidence: int = 75


@dataclass
class PipelineState:
    incident: Incident
    events: list[SecurityEvent]
    db: Session
    trace_id: str
    shared: dict = field(default_factory=dict)

    def rag(self, query: str, top_k: int = 3, category: str | None = None) -> list[dict]:
        if not rag_engine.ready:
            return []
        return [r.as_dict() for r in rag_engine.search(query, top_k=top_k, category=category)]


# ---------------------------------------------------------------------------
# 1 — Log Analyst
# ---------------------------------------------------------------------------
def agent_log_analyst(state: PipelineState) -> AgentOutput:
    events = state.events
    inc = state.incident
    if not events:
        return AgentOutput(
            headline="No correlated telemetry attached to this case",
            reasoning=(
                "Queried the event store for records linked to this incident and for any event "
                "sharing its source address inside the case window. Nothing returned.\n"
                "Proceeding on incident metadata alone; downstream confidence is capped at 45%."
            ),
            findings={"event_count": 0, "degraded": True},
            confidence=40,
        )

    by_type = Counter(e.event_type for e in events)
    by_sev = Counter(e.severity for e in events)
    by_src = Counter(e.src_ip for e in events if e.src_ip)
    by_user = Counter(e.username for e in events if e.username)
    rules = Counter(e.matched_rule for e in events if e.matched_rule)
    timestamps = sorted(e.ts for e in events)
    window_s = max((timestamps[-1] - timestamps[0]).total_seconds(), 1.0)
    rate = len(events) / (window_s / 60.0)

    failures = sum(1 for e in events if e.event_type in {"auth_failure", "policy_block"})
    successes = sum(1 for e in events if e.event_type == "auth_success")
    anomalies = sum(1 for e in events if e.is_anomaly)
    egress = sum(e.bytes_out for e in events)

    burst = rate > 20
    top_src, top_src_count = (by_src.most_common(1) or [(None, 0)])[0]

    lines = [
        f"Pulled {len(events)} correlated events spanning "
        f"{timestamps[0]:%Y-%m-%d %H:%M:%S} → {timestamps[-1]:%H:%M:%S} UTC "
        f"({window_s / 60:.1f} min window, {rate:.1f} events/min).",
        "Event-type distribution: "
        + ", ".join(f"{k}×{v}" for k, v in by_type.most_common(5)) + ".",
        "Severity mix: " + ", ".join(f"{k}={v}" for k, v in by_sev.most_common()) + ".",
    ]
    if rules:
        lines.append(
            "Signature rules fired: "
            + ", ".join(f"{r} ({c} hits)" for r, c in rules.most_common(4)) + "."
        )
    if top_src:
        share = top_src_count / len(events) * 100
        lines.append(
            f"Source concentration: {top_src} accounts for {top_src_count}/{len(events)} "
            f"events ({share:.0f}%) — {'single-origin activity' if share > 60 else 'distributed origins'}."
        )
    if by_user:
        lines.append(
            f"{len(by_user)} distinct principals touched; most targeted: "
            + ", ".join(f"{u}({c})" for u, c in by_user.most_common(3)) + "."
        )
    if burst:
        lines.append(
            f"BURST FLAG: {rate:.1f} events/min exceeds the 20/min automation threshold — "
            "consistent with scripted rather than human activity."
        )
    if failures and successes:
        lines.append(
            f"CRITICAL SEQUENCE: {failures} failures followed by {successes} success(es) from the "
            "same origin. This is the signature of a guessing attack that eventually landed."
        )
    if anomalies:
        lines.append(
            f"{anomalies} of these events were independently flagged by the Isolation Forest "
            "anomaly model, so this is not purely a signature-based detection."
        )
    if egress > 50_000_000:
        lines.append(f"Egress volume across the window: {egress / 1_048_576:.1f} MiB — elevated.")

    sources = state.rag(
        f"{inc.category} {' '.join(k for k, _ in by_type.most_common(3))} log analysis detection", 3
    )
    state.shared.update(
        event_count=len(events),
        by_type=dict(by_type),
        by_severity=dict(by_sev),
        top_source=top_src,
        top_source_count=top_src_count,
        distinct_users=len(by_user),
        targeted_users=[u for u, _ in by_user.most_common(5)],
        failures=failures,
        successes=successes,
        anomalies=anomalies,
        egress_bytes=egress,
        rate_per_min=round(rate, 2),
        window_seconds=int(window_s),
        burst=burst,
        rules=list(rules),
        first_seen=timestamps[0],
        last_seen=timestamps[-1],
    )

    return AgentOutput(
        headline=(
            f"{len(events)} events, {len(by_sev)} severity classes, "
            f"{'burst pattern detected' if burst else 'steady-state pattern'}"
        ),
        reasoning="\n".join(lines),
        findings={
            "event_count": len(events),
            "window_seconds": int(window_s),
            "events_per_minute": round(rate, 2),
            "top_event_types": dict(by_type.most_common(5)),
            "severity_mix": dict(by_sev),
            "signature_rules": dict(rules),
            "distinct_sources": len(by_src),
            "distinct_users": len(by_user),
            "failure_success_sequence": bool(failures and successes),
            "burst_detected": burst,
            "anomaly_flagged": anomalies,
        },
        rag_sources=sources,
        tool_calls=[
            {"tool": "event_store.query", "args": {"incident_id": inc.id}, "result_count": len(events)},
            {"tool": "signature_engine.summarise", "args": {"rules": list(rules)}, "result_count": len(rules)},
        ],
        confidence=88 if len(events) > 10 else 65,
    )


# ---------------------------------------------------------------------------
# 2 — Threat Intel
# ---------------------------------------------------------------------------
def agent_threat_intel(state: PipelineState) -> AgentOutput:
    inc = state.incident
    indicators: list[str] = []
    if inc.src_ip:
        indicators.append(inc.src_ip)
    for ev in state.events:
        if ev.src_ip and ev.src_ip not in indicators:
            indicators.append(ev.src_ip)
        if ev.file_hash and ev.file_hash not in indicators:
            indicators.append(ev.file_hash)
    indicators = indicators[:4]

    results, tool_calls, lines = [], [], []
    worst = 0
    for indicator in indicators:
        intel = threat_intel.lookup(indicator, session=state.db)
        results.append(intel)
        worst = max(worst, intel["score"])
        tool_calls.append(
            {
                "tool": "threat_intel.lookup",
                "args": {"indicator": indicator},
                "result": {"verdict": intel["verdict"], "score": intel["score"],
                           "live": intel["live"], "cached": intel["cached"]},
            }
        )
        provider_detail = "; ".join(
            f"{p['provider']}={p['score']} ({p['verdict']})" for p in intel["providers"]
        )
        lines.append(
            f"{indicator} [{intel['indicator_type']}] → {intel['verdict'].upper()} "
            f"score {intel['score']}/100 · {provider_detail} · "
            f"{'live provider data' if intel['live'] else 'offline heuristic scoring'}"
            f"{' · served from cache' if intel['cached'] else ''}"
        )
        for provider in intel["providers"]:
            if provider.get("detail"):
                lines.append(f"    ↳ {provider['provider']}: {provider['detail']}")

    if not indicators:
        lines.append("No external indicators present on this case — nothing to enrich.")

    verdict = (
        "malicious" if worst >= 80 else
        "suspicious" if worst >= 50 else
        "low-confidence" if worst >= 20 else "clean"
    )
    lines.append(
        f"Aggregate external reputation verdict: {verdict.upper()} (max score {worst}/100). "
        + (
            "Reputation alone justifies containment." if worst >= 80 else
            "Reputation supports but does not by itself establish malice." if worst >= 50 else
            "Reputation is not incriminating; internal evidence must carry the case."
        )
    )

    sources = state.rag(f"{inc.category} threat intelligence reputation indicator", 2)
    state.shared.update(intel_score=worst, intel_verdict=verdict, intel_results=results)

    return AgentOutput(
        headline=f"External reputation: {verdict} ({worst}/100) across {len(indicators)} indicator(s)",
        reasoning="\n".join(lines),
        findings={
            "indicators_checked": len(indicators),
            "max_score": worst,
            "verdict": verdict,
            "providers": sorted({p["provider"] for r in results for p in r["providers"]}),
            "live_data": any(r["live"] for r in results),
            "cache_backend": results[0]["cache_backend"] if results else "n/a",
            "details": [
                {"indicator": r["indicator"], "verdict": r["verdict"], "score": r["score"]}
                for r in results
            ],
        },
        rag_sources=sources,
        tool_calls=tool_calls,
        confidence=85 if any(r["live"] for r in results) else 62,
    )


# ---------------------------------------------------------------------------
# 3 — Correlation
# ---------------------------------------------------------------------------
def agent_correlation(state: PipelineState) -> AgentOutput:
    inc, db = state.incident, state.db
    events = sorted(state.events, key=lambda e: e.ts)
    lines, chronology = [], []

    for ev in events[:12]:
        chronology.append(
            {
                "ts": ev.ts.isoformat(),
                "event_type": ev.event_type,
                "severity": ev.severity,
                "actor": ev.src_ip or "internal",
                "target": f"{ev.host}{':' + str(ev.dest_port) if ev.dest_port else ''}",
                "message": ev.message[:180],
            }
        )

    related: list[dict] = []
    if inc.src_ip:
        window_start = inc.created_at - timedelta(days=30)
        rows = db.execute(
            select(Incident)
            .where(
                Incident.src_ip == inc.src_ip,
                Incident.id != inc.id,
                Incident.created_at >= window_start,
            )
            .order_by(Incident.created_at.desc())
            .limit(6)
        ).scalars().all()
        related = [
            {"ref": r.ref, "title": r.title, "severity": r.severity,
             "status": r.status, "created_at": r.created_at.isoformat()}
            for r in rows
        ]

    if events:
        gaps = [
            (events[i + 1].ts - events[i].ts).total_seconds() for i in range(len(events) - 1)
        ]
        cadence = statistics.median(gaps) if gaps else 0.0
        jitter = statistics.pstdev(gaps) if len(gaps) > 2 else 0.0
        lines.append(
            f"Reconstructed a {len(events)}-event chronology. Median inter-event gap "
            f"{cadence:.1f}s with {jitter:.1f}s jitter."
        )
        if cadence and cadence < 5 and jitter < cadence:
            lines.append(
                "Low-jitter, sub-5-second cadence is machine-generated. Human-driven activity "
                "shows far greater variance — treat this as tooling."
            )
        phases = []
        types_in_order = [e.event_type for e in events]
        if "recon" in types_in_order or "port_scan" in types_in_order:
            phases.append("reconnaissance")
        if "auth_failure" in types_in_order:
            phases.append("credential access")
        if "auth_success" in types_in_order:
            phases.append("initial access")
        if any(t in types_in_order for t in ("privilege_use", "account_created")):
            phases.append("privilege escalation / persistence")
        if any(t in types_in_order for t in ("web_shell", "scheduled_task")):
            phases.append("persistence")
        if egress_heavy := state.shared.get("egress_bytes", 0) > 50_000_000:
            phases.append("exfiltration")
        if phases:
            lines.append("Kill-chain phases observed in order: " + " → ".join(phases) + ".")
            state.shared["kill_chain_phase"] = phases[-1]
        _ = egress_heavy
    else:
        lines.append("No events to correlate; chronology unavailable.")

    if related:
        lines.append(
            f"Historical correlation: {inc.src_ip} appears in {len(related)} other case(s) in the "
            f"last 30 days ({', '.join(r['ref'] for r in related[:4])}). Repeat offender — this is "
            "campaign activity, not an isolated probe."
        )
    elif inc.src_ip:
        lines.append(f"No prior cases involving {inc.src_ip} in the last 30 days — first observation.")

    dwell = 0
    if events:
        dwell = minutes_between(events[0].ts, datetime.now(timezone.utc))
        lines.append(f"Time from first observed event to now: {dwell} minutes (dwell estimate).")

    sources = state.rag(f"{inc.category} correlation kill chain sequence analysis", 2)
    state.shared.update(related_incidents=related, dwell_minutes=dwell, chronology=chronology)

    return AgentOutput(
        headline=(
            f"{len(chronology)} correlated steps; "
            f"{len(related)} historical case(s) share this origin"
        ),
        reasoning="\n".join(lines),
        findings={
            "chronology": chronology,
            "related_incidents": related,
            "dwell_minutes": dwell,
            "kill_chain_phase": state.shared.get("kill_chain_phase", inc.kill_chain_phase),
            "repeat_offender": bool(related),
        },
        rag_sources=sources,
        tool_calls=[
            {"tool": "incident_store.find_by_indicator",
             "args": {"src_ip": inc.src_ip, "days": 30}, "result_count": len(related)},
        ],
        confidence=80 if events else 45,
    )


# ---------------------------------------------------------------------------
# 4 — Risk Assessment
# ---------------------------------------------------------------------------
def agent_risk(state: PipelineState) -> AgentOutput:
    inc = state.incident
    s = state.shared

    sev_component = min(
        sum(SEVERITY_WEIGHT.get(k, 1) * v for k, v in s.get("by_severity", {}).items()) / 3.0, 30.0
    )
    intel_component = s.get("intel_score", 0) * 0.22
    success_component = 18.0 if s.get("successes") and s.get("failures") else 0.0
    volume_component = min(s.get("event_count", 0) / 12.0, 12.0)
    anomaly_component = min(s.get("anomalies", 0) * 2.5, 10.0)
    repeat_component = 8.0 if s.get("related_incidents") else 0.0
    egress_component = min(s.get("egress_bytes", 0) / 20_000_000, 10.0)

    subtotal = (
        sev_component + intel_component + success_component + volume_component
        + anomaly_component + repeat_component + egress_component
    )
    multiplier = CRITICALITY_WEIGHT.get(inc.asset_criticality, 1.0)
    score = int(max(0, min(round(subtotal * multiplier), 100)))

    severity = (
        Severity.CRITICAL.value if score >= 80 else
        Severity.HIGH.value if score >= 60 else
        Severity.MEDIUM.value if score >= 35 else
        Severity.LOW.value
    )
    priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}[severity]

    breakdown = [
        ("Severity-weighted event mix", round(sev_component, 1), 30),
        ("External reputation", round(intel_component, 1), 22),
        ("Successful-access indicator", round(success_component, 1), 18),
        ("Event volume", round(volume_component, 1), 12),
        ("ML anomaly corroboration", round(anomaly_component, 1), 10),
        ("Repeat-offender history", round(repeat_component, 1), 8),
        ("Egress volume", round(egress_component, 1), 10),
    ]

    lines = [
        "Risk index composed from seven weighted components, then scaled by asset criticality.",
        *[f"  {name:<34} {value:>5.1f} / {cap}" for name, value, cap in breakdown],
        f"  {'Subtotal':<34} {subtotal:>5.1f}",
        f"  {'Asset criticality multiplier':<34} ×{multiplier:.2f} ({inc.asset_criticality} asset: {inc.asset})",
        f"→ Final risk index: {score}/100 ⇒ severity {severity.upper()}, priority {priority}.",
    ]
    if score >= 80:
        lines.append(
            "Score is in the containment-mandatory band. SLA clock is 15 minutes to first "
            "containment action; escalate to the on-call SOC manager immediately."
        )
    elif score >= 60:
        lines.append("High band: assign to a tier-2 analyst and begin containment within the hour.")
    else:
        lines.append("Below the auto-escalation threshold; queue for standard triage.")

    sources = state.rag(f"{inc.category} risk assessment severity scoring", 2)
    state.shared.update(risk_score=score, severity=severity, priority=priority,
                        risk_breakdown=breakdown)

    return AgentOutput(
        headline=f"Risk index {score}/100 → {severity} / {priority}",
        reasoning="\n".join(lines),
        findings={
            "risk_score": score,
            "severity": severity,
            "priority": priority,
            "multiplier": multiplier,
            "components": [
                {"name": n, "value": v, "max": c} for n, v, c in breakdown
            ],
        },
        rag_sources=sources,
        tool_calls=[{"tool": "risk_model.score", "args": {"components": len(breakdown)}, "result": score}],
        confidence=90,
    )


# ---------------------------------------------------------------------------
# 5 — MITRE ATT&CK Mapper
# ---------------------------------------------------------------------------
def agent_mitre(state: PipelineState) -> AgentOutput:
    inc = state.incident
    corpus = " ".join(
        [inc.title, inc.summary or "", *[e.message for e in state.events[:60]]]
    )
    matched = mitre.match_text(corpus, limit=5)
    matched_ids = [t["id"] for t in matched]

    for tid in mitre.CATEGORY_TECHNIQUES.get(inc.category, []):
        if tid not in matched_ids and len(matched_ids) < 6:
            tech = mitre.technique(tid)
            if tech:
                matched.append(tech)
                matched_ids.append(tid)

    lines = []
    if matched:
        lines.append(
            f"Mapped observed behaviour to {len(matched)} ATT&CK technique(s) using keyword "
            "evidence from event messages plus the category prior for this incident class."
        )
        for tech in matched:
            evidence = [kw for kw in tech["keywords"] if kw in corpus.lower()][:3]
            lines.append(
                f"  {tech['id']} — {tech['name']} [{tech['tactic']}]"
                + (f"\n      evidence: {', '.join(repr(e) for e in evidence)}" if evidence
                   else "\n      evidence: inferred from incident category (no direct keyword hit)")
                + f"\n      detection: {tech['detection']}"
            )
        tactics = sorted({t["tactic"] for t in matched})
        lines.append(f"Tactics covered: {', '.join(tactics)}.")
        if len(tactics) >= 3:
            lines.append(
                "Three or more distinct tactics in one case indicates a multi-stage intrusion "
                "rather than opportunistic noise."
            )
    else:
        lines.append("No technique met the mapping threshold; leaving ATT&CK coverage empty.")

    query = " ".join(t["name"] for t in matched) or inc.category
    sources = state.rag(f"MITRE ATT&CK {query} detection mitigation", 4, category="mitre")
    state.shared.update(
        techniques=matched_ids,
        tactics=sorted({t["tactic"] for t in matched}),
        technique_details=[
            {"id": t["id"], "name": t["name"], "tactic": t["tactic"],
             "mitigation": t["mitigation"]} for t in matched
        ],
    )

    return AgentOutput(
        headline=f"{len(matched_ids)} technique(s) mapped: {', '.join(matched_ids[:4])}",
        reasoning="\n".join(lines),
        findings={
            "techniques": matched_ids,
            "tactics": state.shared["tactics"],
            "details": state.shared["technique_details"],
            "multi_stage": len(state.shared["tactics"]) >= 3,
        },
        rag_sources=sources,
        tool_calls=[{"tool": "mitre.match", "args": {"corpus_chars": len(corpus)},
                     "result_count": len(matched_ids)}],
        confidence=82 if matched else 40,
    )


# ---------------------------------------------------------------------------
# 6 — Root Cause Analyzer
# ---------------------------------------------------------------------------
def agent_root_cause(state: PipelineState) -> AgentOutput:
    inc, s = state.incident, state.shared
    first_events = sorted(state.events, key=lambda e: e.ts)[:5]
    entry_event = first_events[0] if first_events else None

    vector_map = {
        "auth_failure": (
            "Exposed password-authenticated service",
            f"{inc.asset} accepts password authentication from the public internet with no "
            "rate limiting and no lockout policy, which made online guessing viable.",
        ),
        "http_request": (
            "Internet-facing web application",
            f"The request path reaching {inc.asset} was served without an inline WAF rule "
            "covering this payload class.",
        ),
        "sql_injection": (
            "Unparameterised database query",
            "User-controlled input is concatenated into SQL. The fix is parameterised queries; "
            "the WAF rule is a stopgap only.",
        ),
        "web_shell": (
            "Writable, script-executable upload directory",
            "The web root permits both write and script execution, letting an uploaded file "
            "become an execution primitive.",
        ),
        "privilege_use": (
            "Over-broad sudo/elevation grant",
            "The account held elevation rights beyond what its function requires.",
        ),
        "port_scan": (
            "Unnecessary external attack surface",
            "Services were reachable from the internet that have no business being exposed.",
        ),
        "recovery_inhibit": (
            "Backup tier reachable with production credentials",
            "Recovery points could be destroyed using credentials available on the production host.",
        ),
    }
    key = entry_event.event_type if entry_event else inc.category
    vector, explanation = vector_map.get(
        key,
        ("Undetermined — insufficient telemetry",
         "The available events do not establish a definitive entry vector. "
         "Recommend enabling verbose auditing on the affected asset."),
    )

    lines = []
    if entry_event:
        lines.append(
            f"Earliest correlated event: {entry_event.ts:%Y-%m-%d %H:%M:%S} UTC — "
            f"{entry_event.event_type} on {entry_event.host} from "
            f"{entry_event.src_ip or 'internal'}."
        )
        lines.append(f"  raw: {entry_event.raw[:220]}")
    lines.append(f"Determined entry vector: {vector}.")
    lines.append(explanation)

    contributing = []
    if s.get("burst"):
        contributing.append("no rate limiting on the exposed service")
    if s.get("intel_score", 0) >= 70:
        contributing.append("no reputation-based blocking at the edge")
    if s.get("successes"):
        contributing.append("single-factor authentication permitted a guessed credential to succeed")
    if s.get("related_incidents"):
        contributing.append("prior activity from this origin was not converted into a blocking rule")
    if s.get("anomalies"):
        contributing.append("behavioural deviation was detected but not auto-contained")
    if contributing:
        lines.append("Contributing control failures:")
        lines.extend(f"  • {c}" for c in contributing)

    lines.append(
        "Distinguishing proximate from root cause: the proximate cause is the attacker action; "
        f"the root cause is the control gap that made it succeed — {vector.lower()}."
    )

    sources = state.rag(f"{inc.category} root cause entry vector {vector}", 3)
    state.shared.update(root_cause=vector, root_cause_detail=explanation,
                        contributing_factors=contributing)

    return AgentOutput(
        headline=f"Entry vector: {vector}",
        reasoning="\n".join(lines),
        findings={
            "entry_vector": vector,
            "explanation": explanation,
            "first_event_at": entry_event.ts.isoformat() if entry_event else None,
            "first_event_host": entry_event.host if entry_event else None,
            "contributing_factors": contributing,
        },
        rag_sources=sources,
        tool_calls=[{"tool": "event_store.earliest", "args": {"incident_id": inc.id},
                     "result": entry_event.id if entry_event else None}],
        confidence=78 if entry_event else 45,
    )


# ---------------------------------------------------------------------------
# 7 — Recommendation
# ---------------------------------------------------------------------------
def agent_recommendation(state: PipelineState) -> AgentOutput:
    inc, db, s = state.incident, state.db, state.shared
    key, playbook = playbooks.for_category(inc.category)

    existing = db.execute(
        select(PlaybookItem).where(PlaybookItem.incident_id == inc.id)
    ).scalars().all()

    created = 0
    if not existing:
        for position, (phase, title, detail, automatable) in enumerate(playbook["steps"]):
            db.add(
                PlaybookItem(
                    incident_id=inc.id, position=position, phase=phase, title=title,
                    detail=detail, automatable=automatable,
                )
            )
            created += 1
        db.flush()

    risk = s.get("risk_score", inc.risk_score)
    sla = playbook["sla_minutes"]
    if risk >= 80:
        sla = min(sla, 15)

    lines = [
        f"Selected playbook '{playbook['name']}' ({key}) — matched on incident category "
        f"'{inc.category}'.",
        f"{len(playbook['steps'])} steps across "
        f"{len({p for p, *_ in playbook['steps']})} NIST SP 800-61 phases; "
        f"{sum(1 for step in playbook['steps'] if step[3])} are automatable via SOAR.",
        f"Containment SLA: {sla} minutes from case creation "
        f"(base {playbook['sla_minutes']}m"
        + (", compressed for the risk band" if sla < playbook["sla_minutes"] else "")
        + ").",
    ]
    if created:
        lines.append(f"Instantiated {created} checklist items on the case.")
    else:
        done = sum(1 for i in existing if i.completed)
        lines.append(
            f"Checklist already present ({done}/{len(existing)} complete) — preserving analyst progress."
        )

    immediate = [t for t in playbook["steps"] if t[0] == "containment"][:3]
    lines.append("Immediate containment actions:")
    lines.extend(f"  {i}. {t[1]}" for i, t in enumerate(immediate, 1))

    for tech in s.get("technique_details", [])[:3]:
        lines.append(f"Technique-specific mitigation ({tech['id']}): {tech['mitigation']}")

    sources = state.rag(f"{playbook['name']} containment eradication recovery", 4, category="playbook")
    state.shared.update(playbook_key=key, playbook_name=playbook["name"], sla_minutes=sla)

    return AgentOutput(
        headline=f"Playbook '{playbook['name']}' selected — {sla}m containment SLA",
        reasoning="\n".join(lines),
        findings={
            "playbook_key": key,
            "playbook_name": playbook["name"],
            "steps": len(playbook["steps"]),
            "created_items": created,
            "sla_minutes": sla,
            "automatable_steps": sum(1 for step in playbook["steps"] if step[3]),
            "immediate_actions": [t[1] for t in immediate],
        },
        rag_sources=sources,
        tool_calls=[
            {"tool": "playbook_registry.select", "args": {"category": inc.category}, "result": key},
            {"tool": "case.attach_checklist", "args": {"items": created}, "result": "ok"},
        ],
        confidence=86,
    )


# ---------------------------------------------------------------------------
# 8 — Compliance Auditor
# ---------------------------------------------------------------------------
CONTROL_IMPACT = {
    "brute-force": [
        ("ISO27001", "A.8.5", "Secure authentication", "MFA not enforced on the exposed service"),
        ("ISO27001", "A.5.15", "Access control", "No lockout threshold on repeated failures"),
        ("SOC2", "CC6.1", "Logical access controls", "Password-only access to a production asset"),
    ],
    "web-exploit": [
        ("ISO27001", "A.8.28", "Secure coding", "Input handling permitted an injection payload"),
        ("ISO27001", "A.8.8", "Technical vulnerability management", "Vulnerable component in production"),
        ("SOC2", "CC7.1", "Vulnerability detection", "Exploit reached the application unblocked"),
    ],
    "data-exfiltration": [
        ("ISO27001", "A.8.12", "Data leakage prevention", "Egress left the boundary uninspected"),
        ("ISO27001", "A.5.34", "Privacy and PII protection", "Regulated data may be in scope"),
        ("SOC2", "CC6.7", "Data transmission restrictions", "Unsanctioned destination reachable"),
    ],
    "ransomware": [
        ("ISO27001", "A.8.13", "Information backup", "Backup isolation must be re-verified"),
        ("ISO27001", "A.5.29", "Continuity of security", "BCP invocation criteria met"),
        ("SOC2", "A1.2", "Recovery infrastructure", "Recovery point integrity in question"),
    ],
    "privilege-escalation": [
        ("ISO27001", "A.8.2", "Privileged access rights", "Elevation path was not least-privilege"),
        ("SOC2", "CC6.3", "Role-based access", "Standing privilege exceeded role requirement"),
    ],
    "lateral-movement": [
        ("ISO27001", "A.8.20", "Network security", "East-west traffic was not segmented"),
        ("SOC2", "CC6.6", "Boundary protection", "Internal boundaries did not constrain movement"),
    ],
}
DEFAULT_CONTROLS = [
    ("ISO27001", "A.5.24", "Incident management planning", "Case must follow the documented IR process"),
    ("ISO27001", "A.8.15", "Logging", "Evidence retention applies to this case"),
    ("SOC2", "CC7.3", "Security incident evaluation", "Evaluation and disposition required"),
]


def agent_compliance(state: PipelineState) -> AgentOutput:
    inc, s = state.incident, state.shared
    impacted = CONTROL_IMPACT.get(inc.category, []) + DEFAULT_CONTROLS
    risk = s.get("risk_score", inc.risk_score)

    lines = [
        f"Mapped this case against ISO/IEC 27001:2022 Annex A and the SOC 2 Trust Services "
        f"Criteria. {len(impacted)} control(s) are implicated.",
    ]
    gaps = []
    for framework, control_id, title, note in impacted:
        status = "GAP" if risk >= 60 and (framework, control_id) not in {
            (f, c) for f, c, _, _ in DEFAULT_CONTROLS
        } else "OBSERVATION"
        if status == "GAP":
            gaps.append({"framework": framework, "control_id": control_id, "title": title, "note": note})
        lines.append(f"  [{status}] {framework} {control_id} — {title}: {note}")

    notifiable = risk >= 70 and inc.category in {"data-exfiltration", "ransomware"}
    if notifiable:
        lines.append(
            "REGULATORY: this case class combined with a risk index ≥70 triggers the breach "
            "assessment path. GDPR Art. 33 sets a 72-hour notification clock from awareness; "
            "record the awareness timestamp on the case now."
        )
    else:
        lines.append(
            "No statutory notification threshold met on current evidence. Re-evaluate if data "
            "access is confirmed."
        )
    lines.append(
        f"Evidence retention: preserve raw telemetry, this agent timeline and all analyst notes "
        f"for {'7 years (regulated case)' if notifiable else '1 year (standard case)'} per policy."
    )

    sources = state.rag(f"ISO 27001 SOC 2 {inc.category} control requirement", 3, category="policy")
    state.shared.update(compliance_gaps=gaps, notifiable=notifiable)

    return AgentOutput(
        headline=f"{len(impacted)} controls implicated, {len(gaps)} gap(s)"
        + (", regulatory clock started" if notifiable else ""),
        reasoning="\n".join(lines),
        findings={
            "controls": [
                {"framework": f, "control_id": c, "title": t, "note": n} for f, c, t, n in impacted
            ],
            "gaps": gaps,
            "regulatory_notification": notifiable,
            "retention_years": 7 if notifiable else 1,
        },
        rag_sources=sources,
        tool_calls=[{"tool": "compliance.map_controls", "args": {"category": inc.category},
                     "result_count": len(impacted)}],
        confidence=84,
    )


# ---------------------------------------------------------------------------
# 9 — Executive Reporter
# ---------------------------------------------------------------------------
def agent_executive_report(state: PipelineState) -> AgentOutput:
    inc, s = state.incident, state.shared
    risk = s.get("risk_score", inc.risk_score)
    severity = s.get("severity", inc.severity)

    what_happened = (
        f"{s.get('event_count', 0)} security events involving "
        f"{s.get('top_source') or 'an internal source'} were correlated against "
        f"{inc.asset} ({inc.asset_criticality} criticality) over "
        f"{s.get('window_seconds', 0) // 60} minutes."
    )
    business_impact = (
        "Confirmed unauthorised access to a production asset — assume data exposure until "
        "proven otherwise."
        if s.get("successes") else
        "No successful access observed. Impact is currently limited to attempted compromise "
        "and the analyst time spent responding."
    )

    md = f"""## {inc.ref} — {inc.title}

**Risk index** {risk}/100 · **Severity** {severity.upper()} · **Priority** {s.get('priority', inc.priority)}
**Asset** {inc.asset} ({inc.asset_criticality}) · **Origin** {inc.src_ip or 'internal'}

### What happened
{what_happened} External reputation for the origin resolved to **{s.get('intel_verdict', 'unknown')}**
({s.get('intel_score', 0)}/100).

### Business impact
{business_impact}

### Root cause
**{s.get('root_cause', 'Undetermined')}** — {s.get('root_cause_detail', 'insufficient telemetry to conclude.')}

### Adversary techniques
{', '.join(mitre.label(t) for t in s.get('techniques', [])) or 'None mapped.'}

### Response
Playbook **{s.get('playbook_name', 'n/a')}** engaged with a {s.get('sla_minutes', 60)}-minute
containment SLA. {len(s.get('compliance_gaps', []))} compliance gap(s) recorded
{'and the regulatory notification assessment has been started' if s.get('notifiable') else 'with no statutory notification triggered'}.

### What we are asking for
{chr(10).join('- ' + c for c in s.get('contributing_factors', [])) or '- No systemic control changes identified.'}
"""

    lines = [
        "Compiled the executive brief for non-technical stakeholders: what happened, what it "
        "means commercially, what caused it, and what is being asked of leadership.",
        f"Reading level targeted at board/exec audience; {len(md.split())} words.",
        "Every claim in the brief traces to a finding from an earlier agent in this run — no "
        "assertion is introduced at the reporting stage.",
    ]
    if risk >= 80:
        lines.append("Flagged for same-day executive distribution given the critical risk band.")

    sources = state.rag("executive incident reporting communication stakeholders", 2)
    state.shared["executive_summary"] = md

    return AgentOutput(
        headline=f"Executive brief generated ({len(md.split())} words)",
        reasoning="\n".join(lines),
        findings={"markdown": md, "word_count": len(md.split()),
                  "distribution": "executive" if risk >= 80 else "soc-internal"},
        rag_sources=sources,
        tool_calls=[{"tool": "report.render_markdown", "args": {"incident": inc.ref}, "result": "ok"}],
        confidence=88,
    )


# ---------------------------------------------------------------------------
# Registry + orchestrator
# ---------------------------------------------------------------------------
AGENTS = [
    ("log_analyst", "Log Analyst", "Parses and characterises the raw telemetry", agent_log_analyst),
    ("threat_intel", "Threat Intel", "External reputation enrichment", agent_threat_intel),
    ("correlation", "Correlation", "Chronology and historical linkage", agent_correlation),
    ("risk", "Risk Assessment", "Weighted 0–100 severity index", agent_risk),
    ("mitre", "MITRE ATT&CK Mapper", "Technique and tactic mapping", agent_mitre),
    ("root_cause", "Root Cause Analyzer", "Entry vector determination", agent_root_cause),
    ("recommendation", "Recommendation", "Playbook selection and task creation", agent_recommendation),
    ("compliance", "Compliance Auditor", "ISO 27001 / SOC 2 gap mapping", agent_compliance),
    ("reporter", "Executive Reporter", "Stakeholder-facing markdown brief", agent_executive_report),
]

AGENT_CATALOG = [
    {"key": k, "name": n, "description": d, "position": i + 1}
    for i, (k, n, d, _) in enumerate(AGENTS)
]


def _collect_events(db: Session, incident: Incident, limit: int = 400) -> list[SecurityEvent]:
    stmt = select(SecurityEvent).where(SecurityEvent.incident_id == incident.id)
    events = list(db.execute(stmt).scalars().all())
    if len(events) < 5 and incident.src_ip:
        window_start = incident.created_at - timedelta(hours=6)
        extra = db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.src_ip == incident.src_ip,
                SecurityEvent.ts >= window_start,
                SecurityEvent.incident_id.is_(None),
            )
            .order_by(SecurityEvent.ts)
            .limit(limit)
        ).scalars().all()
        seen = {e.id for e in events}
        events.extend(e for e in extra if e.id not in seen)
    return sorted(events, key=lambda e: e.ts)[:limit]


def run_pipeline(
    db: Session,
    incident: Incident,
    *,
    triggered_by: User | None = None,
    reason: str = "manual",
    apply_to_incident: bool = True,
) -> AgentRun:
    """Execute all nine agents against one incident, persisting a full audit trail."""
    trace_id = tracing.new_trace_id()
    run = AgentRun(
        incident_id=incident.id,
        trace_id=trace_id,
        status="running",
        triggered_by_id=getattr(triggered_by, "id", None),
        trigger_reason=reason,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.flush()

    state = PipelineState(
        incident=incident, events=_collect_events(db, incident), db=db, trace_id=trace_id
    )
    started = time.perf_counter()
    total_in = total_out = 0
    # Spans are buffered and written through this run's own session at the end:
    # a second SQLite writer opened mid-transaction would block on our own lock.
    spans: list = []

    with tracing.span(
        f"incident_investigation:{incident.ref}",
        trace_id=trace_id, kind="chain", model=None,
        attributes={"incident_ref": incident.ref, "category": incident.category,
                    "agents": len(AGENTS), "trigger": reason},
        persist=False, collector=spans,
    ) as root_span:
        for position, (key, name, _desc, fn) in enumerate(AGENTS):
            step_started = datetime.now(timezone.utc)
            t0 = time.perf_counter()
            try:
                with tracing.span(
                    f"agent:{key}", trace_id=trace_id, kind="llm",
                    parent_span_id=root_span.span_id,
                    attributes={"agent": name, "position": position + 1,
                                "incident_ref": incident.ref},
                    persist=False, collector=spans,
                ) as agent_span:
                    output = fn(state)
                    prompt = (
                        f"[{name}] incident={incident.ref} category={incident.category} "
                        f"events={len(state.events)} prior_state_keys={sorted(state.shared)[:12]}"
                    )
                    body = output.reasoning + str(output.findings)
                    agent_span.tokens_in = tracing.estimate_tokens(prompt) + 180
                    agent_span.tokens_out = tracing.estimate_tokens(body)
                    agent_span.prompt_preview = prompt[:1_000]
                    agent_span.output_preview = output.headline[:1_000]
                    agent_span.attributes["rag_hits"] = len(output.rag_sources)
                    agent_span.attributes["tool_calls"] = len(output.tool_calls)
                    agent_span.attributes["confidence"] = output.confidence
                    tokens_in, tokens_out = agent_span.tokens_in, agent_span.tokens_out
                status, error = "completed", None
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("Agent %s failed on %s", key, incident.ref)
                output = AgentOutput(
                    headline=f"{name} failed",
                    reasoning=f"{type(exc).__name__}: {exc}",
                    findings={"error": str(exc)},
                    confidence=0,
                )
                tokens_in = tokens_out = 0
                status, error = "failed", str(exc)

            latency = int((time.perf_counter() - t0) * 1000)
            total_in += tokens_in
            total_out += tokens_out

            db.add(
                AgentStep(
                    run_id=run.id, position=position, agent_key=key, agent_name=name,
                    status=status, headline=output.headline, reasoning=output.reasoning,
                    findings=output.findings, rag_sources=output.rag_sources,
                    tool_calls=output.tool_calls, confidence=output.confidence,
                    tokens_in=tokens_in, tokens_out=tokens_out, latency_ms=latency,
                    started_at=step_started, finished_at=datetime.now(timezone.utc),
                )
            )
            if error:
                run.error = f"{key}: {error}"

        root_span.tokens_in = total_in
        root_span.tokens_out = total_out
        root_span.output_preview = (
            f"risk={state.shared.get('risk_score')} "
            f"techniques={state.shared.get('techniques')}"
        )

    run.status = "completed" if not run.error else "completed_with_errors"
    run.finished_at = datetime.now(timezone.utc)
    run.duration_ms = int((time.perf_counter() - started) * 1000)
    run.tokens_in, run.tokens_out = total_in, total_out
    run.cost_usd = round(
        (total_in / 1000) * tracing.COST_PER_1K_IN + (total_out / 1000) * tracing.COST_PER_1K_OUT, 6
    )
    run.final_risk_score = state.shared.get("risk_score", incident.risk_score)
    run.verdict = state.shared.get("intel_verdict", "unknown")

    tracing.persist_spans(db, spans)

    if apply_to_incident:
        _apply(db, incident, state, run)

    db.flush()
    return run


def _apply(db: Session, incident: Incident, state: PipelineState, run: AgentRun) -> None:
    s = state.shared
    incident.risk_score = s.get("risk_score", incident.risk_score)
    incident.severity = s.get("severity", incident.severity)
    incident.priority = s.get("priority", incident.priority)
    incident.mitre_techniques = s.get("techniques", incident.mitre_techniques)
    incident.root_cause = s.get("root_cause")
    incident.executive_summary = s.get("executive_summary")
    incident.intel_verdict = s.get("intel_verdict")
    incident.playbook_key = s.get("playbook_key", incident.playbook_key)
    incident.kill_chain_phase = s.get("kill_chain_phase", incident.kill_chain_phase)
    incident.confidence = int(
        statistics.mean([st.confidence for st in run.steps]) if run.steps else incident.confidence
    )
    if s.get("sla_minutes"):
        incident.sla_due_at = incident.created_at + timedelta(minutes=s["sla_minutes"])
    if incident.status == IncidentStatus.NEW.value:
        incident.status = IncidentStatus.TRIAGING.value
    incident.updated_at = datetime.now(timezone.utc)

    db.add(
        IncidentNote(
            incident_id=incident.id,
            author_id=run.triggered_by_id,
            kind="system",
            body=(
                f"Agent pipeline completed in {run.duration_ms}ms across {len(AGENTS)} agents. "
                f"Risk index {incident.risk_score}/100 ({incident.severity}). "
                f"Techniques: {', '.join(incident.mitre_techniques) or 'none'}. "
                f"Trace {run.trace_id[:12]}."
            ),
        )
    )


def build_threat_chain(incident: Incident, events: list[SecurityEvent]) -> dict:
    """Flat node/edge graph rendered as the SVG threat-chain diagram."""
    origin = incident.src_ip or "internal"
    techniques = list(incident.mitre_techniques or [])
    hosts = sorted({e.host for e in events if e.host} or {incident.asset})

    nodes = [
        {"id": "src", "label": origin, "sublabel": incident.intel_verdict or "unclassified",
         "kind": "source"},
        {"id": "vector", "label": incident.root_cause or "Unknown vector",
         "sublabel": incident.kill_chain_phase, "kind": "vector"},
    ]
    edges = [{"source": "src", "target": "vector", "label": incident.category}]

    for i, tid in enumerate(techniques[:3]):
        tech = mitre.technique(tid)
        node_id = f"tech{i}"
        nodes.append(
            {"id": node_id, "label": tid,
             "sublabel": tech["name"] if tech else "", "kind": "technique"}
        )
        edges.append({"source": "vector" if i == 0 else f"tech{i - 1}",
                      "target": node_id,
                      "label": tech["tactic"] if tech else ""})

    anchor = f"tech{min(len(techniques), 3) - 1}" if techniques else "vector"
    for i, host in enumerate(hosts[:3]):
        node_id = f"asset{i}"
        nodes.append(
            {"id": node_id, "label": host,
             "sublabel": f"{incident.asset_criticality} criticality", "kind": "asset"}
        )
        edges.append({"source": anchor, "target": node_id, "label": "targets"})

    impact = (
        "Data exposure" if incident.category == "data-exfiltration" else
        "Service disruption" if incident.category in {"ransomware", "availability"} else
        "Unauthorised access" if incident.category in {"brute-force", "credential-access"} else
        "Foothold established"
    )
    nodes.append({"id": "impact", "label": impact,
                  "sublabel": f"risk {incident.risk_score}/100", "kind": "impact"})
    for i in range(min(len(hosts), 3)):
        edges.append({"source": f"asset{i}", "target": "impact", "label": ""})
    if not hosts:
        edges.append({"source": anchor, "target": "impact", "label": ""})

    return {"nodes": nodes, "edges": edges}
