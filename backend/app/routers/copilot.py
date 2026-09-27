"""Security Copilot — retrieval-augmented Q&A grounded in the knowledge base
and the live case/telemetry data, plus direct access to the RAG index.

Answers are composed deterministically from retrieved documents and live SQL
aggregates. Every claim is traceable to a cited source or a query result, which
is the property that matters in a SOC: an assistant that cannot show its
evidence cannot be acted on.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, record_audit, require_capability
from ..models import CopilotMessage, Incident, SecurityEvent, User
from ..schemas import CopilotReply, CopilotRequest, RagHit, RagQuery
from ..services import mitre, tracing
from ..services.rag import engine as rag_engine

router = APIRouter(tags=["copilot"])

SUGGESTED_PROMPTS = [
    "What are the highest-risk open incidents right now?",
    "Explain T1110 and how we detect it",
    "How should I respond to a suspected web shell?",
    "Which ATT&CK techniques are we seeing most this week?",
    "What is our breach notification obligation for a data exfiltration case?",
    "Summarise activity from 45.155.205.233",
]


# ---------------------------------------------------------------------------
# RAG surface
# ---------------------------------------------------------------------------
@router.post("/rag/search", response_model=list[RagHit], summary="Search the knowledge base")
def rag_search(
    payload: RagQuery, _user: User = Depends(get_current_user)
) -> list[RagHit]:
    hits = rag_engine.search(payload.query, top_k=payload.top_k, category=payload.category)
    return [RagHit(**h.as_dict()) for h in hits]


@router.get("/rag/status", summary="Index backend and document count")
def rag_status(_user: User = Depends(get_current_user)) -> dict:
    return rag_engine.describe()


@router.post("/rag/reindex", summary="Rebuild the vector index from the database")
def rag_reindex(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("settings:write")),
) -> dict:
    from ..services.rag import rebuild_from_db

    stats = rebuild_from_db()
    record_audit(db, actor=user, action="rag.reindex", target_type="index",
                 target_id="knowledge", detail=str(stats), request=request)
    db.commit()
    return stats


# ---------------------------------------------------------------------------
# Copilot chat
# ---------------------------------------------------------------------------
@router.get("/copilot/history", summary="Chat history for a session")
def history(
    session_key: str = Query(default="default"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    rows = db.execute(
        select(CopilotMessage)
        .where(CopilotMessage.session_key == session_key, CopilotMessage.user_id == user.id)
        .order_by(CopilotMessage.created_at)
        .limit(limit)
    ).scalars().all()
    return {
        "session_key": session_key,
        "messages": [
            {"role": m.role, "content": m.content, "citations": m.citations,
             "created_at": m.created_at, "latency_ms": m.latency_ms}
            for m in rows
        ],
        "suggested": SUGGESTED_PROMPTS,
    }


@router.post("/copilot/chat", response_model=CopilotReply, summary="Ask the Security Copilot")
def chat(
    payload: CopilotRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability("copilot:chat")),
) -> CopilotReply:
    started = time.perf_counter()
    trace_id = tracing.new_trace_id()
    question = payload.message.strip()

    db.add(CopilotMessage(session_key=payload.session_key, user_id=user.id,
                          role="user", content=question))

    spans: list = []

    with tracing.span("copilot:retrieve", trace_id=trace_id, kind="retriever",
                      persist=False, collector=spans) as span:
        hits = rag_engine.search(question, top_k=5)
        span.tokens_in = tracing.estimate_tokens(question)
        span.prompt_preview = question[:500]
        span.output_preview = f"{len(hits)} documents retrieved"
        span.attributes["backend"] = rag_engine.describe().get("vector_backend")

    with tracing.span("copilot:compose", trace_id=trace_id, kind="llm",
                      persist=False, collector=spans) as span:
        answer = _compose(db, question, hits, payload.incident_ref)
        span.tokens_in = tracing.estimate_tokens(question) + sum(
            tracing.estimate_tokens(h.snippet) for h in hits
        )
        span.tokens_out = tracing.estimate_tokens(answer)
        span.prompt_preview = question[:500]
        span.output_preview = answer[:800]
        tokens_in, tokens_out = span.tokens_in, span.tokens_out

    tracing.persist_spans(db, spans)
    latency = int((time.perf_counter() - started) * 1000)
    citations = [h.as_dict() for h in hits]
    db.add(CopilotMessage(session_key=payload.session_key, user_id=user.id, role="assistant",
                          content=answer, citations=citations, latency_ms=latency))
    record_audit(db, actor=user, action="copilot.chat", target_type="copilot",
                 target_id=payload.session_key, request=request)
    db.commit()

    return CopilotReply(
        reply=answer,
        citations=[RagHit(**c) for c in citations],
        latency_ms=latency,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        trace_id=trace_id,
    )


# ---------------------------------------------------------------------------
def _compose(db: Session, question: str, hits, incident_ref: str | None) -> str:
    lowered = question.lower()
    parts: list[str] = []

    ref_match = re.search(r"\b(INC|SIM)-\d{4}-\d+\b", question.upper()) or (
        re.match(r"^$", "") if not incident_ref else None
    )
    ref = ref_match.group(0) if ref_match else incident_ref
    if ref:
        incident = db.execute(select(Incident).where(Incident.ref == ref)).scalar_one_or_none()
        if incident:
            parts.append(_incident_brief(incident))

    if any(k in lowered for k in ("highest", "top", "worst", "riskiest", "priority", "open incident")):
        parts.append(_top_incidents(db))

    if any(k in lowered for k in ("technique", "att&ck", "attack", "mitre", "tactic")):
        parts.append(_technique_summary(db, question))

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
    if ip_match:
        parts.append(_ip_summary(db, ip_match.group(0)))

    if any(k in lowered for k in ("how many", "count", "volume", "statistics", "stats", "this week")):
        parts.append(_stats(db))

    if hits:
        parts.append(_knowledge_answer(hits))
    elif not parts:
        parts.append(
            "I could not retrieve anything relevant from the knowledge base for that. Try naming "
            "an ATT&CK technique (for example T1110), an incident reference (INC-2026-1004), an "
            "IP address, or a response phase such as containment or eradication."
        )

    parts.append(
        "_Grounding: every statement above comes from either a cited knowledge-base document or "
        "a live query against the case and event stores. Nothing is inferred beyond those._"
    )
    return "\n\n".join(p for p in parts if p)


def _incident_brief(incident: Incident) -> str:
    techniques = ", ".join(mitre.label(t) for t in (incident.mitre_techniques or [])) or "none mapped"
    return (
        f"**{incident.ref} — {incident.title}**\n\n"
        f"- Severity **{incident.severity}** · priority {incident.priority} · "
        f"risk index **{incident.risk_score}/100** · status `{incident.status}`\n"
        f"- Asset `{incident.asset}` ({incident.asset_criticality} criticality), "
        f"origin `{incident.src_ip or 'internal'}`"
        + (f", external reputation **{incident.intel_verdict}**" if incident.intel_verdict else "")
        + f"\n- Techniques: {techniques}\n"
        f"- Root cause: {incident.root_cause or 'not yet determined — run the agent pipeline'}\n\n"
        f"{incident.summary}"
    )


def _top_incidents(db: Session) -> str:
    rows = db.execute(
        select(Incident)
        .where(Incident.status.notin_(["closed", "false_positive"]))
        .order_by(desc(Incident.risk_score))
        .limit(5)
    ).scalars().all()
    if not rows:
        return "**Open queue:** nothing open right now — every case is closed or a false positive."
    lines = ["**Highest-risk open cases**", ""]
    for r in rows:
        lines.append(
            f"1. `{r.ref}` — {r.title} · **{r.risk_score}/100** ({r.severity}) · "
            f"status `{r.status}` · asset `{r.asset}`"
        )
    lines.append("")
    lines.append(
        "Work these top-down: risk index already folds in reputation, asset criticality and "
        "whether access actually succeeded."
    )
    return "\n".join(lines)


def _technique_summary(db: Session, question: str) -> str:
    explicit = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", question.upper())
    if explicit:
        lines = []
        for tid in explicit[:3]:
            tech = mitre.technique(tid)
            if not tech:
                lines.append(f"`{tid}` is not in the curated technique set for this deployment.")
                continue
            count = db.execute(
                select(func.count()).select_from(Incident)
                .where(Incident.mitre_techniques.isnot(None))
            ).scalar_one()
            lines.append(
                f"**{tech['id']} — {tech['name']}** ({tech['tactic']})\n\n"
                f"{tech['description']}\n\n"
                f"**Detection:** {tech['detection']}\n\n"
                f"**Mitigation:** {tech['mitigation']}\n\n"
                f"_Observed across {count} case(s) with technique mappings in this tenant._"
            )
        return "\n\n".join(lines)

    since = datetime.now(timezone.utc) - timedelta(days=7)
    rows = db.execute(
        select(Incident.mitre_techniques).where(Incident.created_at >= since)
    ).scalars().all()
    counts: dict[str, int] = {}
    for techniques in rows:
        for tid in techniques or []:
            counts[tid] = counts.get(tid, 0) + 1
    if not counts:
        return "**Technique coverage:** no techniques mapped on cases from the last seven days."
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:6]
    lines = ["**Most-observed ATT&CK techniques (last 7 days)**", ""]
    for tid, count in ranked:
        tech = mitre.technique(tid)
        lines.append(
            f"- `{tid}` {tech['name'] if tech else ''} — {count} case(s)"
            + (f" · {tech['tactic']}" if tech else "")
        )
    return "\n".join(lines)


def _ip_summary(db: Session, ip: str) -> str:
    total = db.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.src_ip == ip)
    ).scalar_one()
    incidents = db.execute(
        select(Incident).where(Incident.src_ip == ip).order_by(desc(Incident.created_at)).limit(5)
    ).scalars().all()
    if not total and not incidents:
        return f"**`{ip}`** does not appear anywhere in the event store or the case history."

    types = db.execute(
        select(SecurityEvent.event_type, func.count())
        .where(SecurityEvent.src_ip == ip)
        .group_by(SecurityEvent.event_type)
        .order_by(func.count().desc())
        .limit(5)
    ).all()
    lines = [
        f"**Activity summary for `{ip}`**", "",
        f"- {total} event(s) in the store",
        "- Event types: " + (", ".join(f"{t} ×{c}" for t, c in types) or "none"),
        "- Linked cases: " + (", ".join(f"`{i.ref}`" for i in incidents) or "none"),
    ]
    if len(incidents) > 1:
        lines.append(
            "- This origin appears in more than one case, which makes it campaign activity "
            "rather than an isolated probe. Consider a durable perimeter block."
        )
    return "\n".join(lines)


def _stats(db: Session) -> str:
    now = datetime.now(timezone.utc)
    day = now - timedelta(hours=24)
    week = now - timedelta(days=7)
    open_cases = db.execute(
        select(func.count()).select_from(Incident)
        .where(Incident.status.notin_(["closed", "false_positive"]))
    ).scalar_one()
    critical = db.execute(
        select(func.count()).select_from(Incident)
        .where(Incident.severity == "critical",
               Incident.status.notin_(["closed", "false_positive"]))
    ).scalar_one()
    events_24h = db.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.ts >= day)
    ).scalar_one()
    cases_week = db.execute(
        select(func.count()).select_from(Incident).where(Incident.created_at >= week)
    ).scalar_one()
    return (
        "**Current posture**\n\n"
        f"- {open_cases} open case(s), {critical} of them critical\n"
        f"- {events_24h:,} events ingested in the last 24 hours\n"
        f"- {cases_week} case(s) opened in the last 7 days"
    )


def _knowledge_answer(hits) -> str:
    lines = ["**From the knowledge base**", ""]
    for hit in hits[:3]:
        lines.append(f"**{hit.title}** _({hit.category})_")
        lines.append(hit.snippet)
        lines.append("")
    lines.append(
        "Sources: " + ", ".join(f"`{h.doc_key}`" for h in hits[:5])
    )
    return "\n".join(lines)


@router.get("/copilot/suggestions", summary="Suggested prompts")
def suggestions(_user: User = Depends(get_current_user)) -> dict:
    return {"suggestions": SUGGESTED_PROMPTS}
