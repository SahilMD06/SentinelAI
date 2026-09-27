"""ORM model layer for SentinelAI.

Column types are deliberately portable (JSON, not JSONB; String, not ARRAY) so
the identical schema materialises on both PostgreSQL and the offline SQLite
fallback without migration branching.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default=Role.VIEWER.value, nullable=False)
    job_title: Mapped[str] = mapped_column(String(120), default="Security Staff")
    team: Mapped[str] = mapped_column(String(120), default="SOC")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local")
    external_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    incidents = relationship("Incident", back_populates="assignee", foreign_keys="Incident.assignee_id")
    notes = relationship("IncidentNote", back_populates="author", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    source: Mapped[str] = mapped_column(String(48), index=True)  # sshd, nginx, winauth...
    host: Mapped[str] = mapped_column(String(96), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(64))
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    username: Mapped[str | None] = mapped_column(String(96), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value, index=True)
    action: Mapped[str | None] = mapped_column(String(32))  # allow / deny / block
    status_code: Mapped[int | None] = mapped_column(Integer)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    geo_country: Mapped[str | None] = mapped_column(String(4))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    file_hash: Mapped[str | None] = mapped_column(String(96), index=True)
    matched_rule: Mapped[str | None] = mapped_column(String(96), index=True)
    message: Mapped[str] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), index=True)

    incident = relationship("Incident", back_populates="events")

    __table_args__ = (
        Index("ix_events_ts_sev", "ts", "severity"),
        Index("ix_events_src_type", "src_ip", "event_type"),
    )


# ---------------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------------
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    ref: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True, default=Severity.MEDIUM.value)
    status: Mapped[str] = mapped_column(String(24), index=True, default=IncidentStatus.NEW.value)
    priority: Mapped[str] = mapped_column(String(8), default="P3")
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    category: Mapped[str] = mapped_column(String(64), index=True, default="intrusion-attempt")
    detection_source: Mapped[str] = mapped_column(String(48), default="signature")
    asset: Mapped[str] = mapped_column(String(120), default="unknown")
    asset_criticality: Mapped[str] = mapped_column(String(16), default="medium")
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(64))
    affected_user: Mapped[str | None] = mapped_column(String(96))
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    kill_chain_phase: Mapped[str] = mapped_column(String(48), default="reconnaissance")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    playbook_key: Mapped[str | None] = mapped_column(String(64))
    root_cause: Mapped[str | None] = mapped_column(Text)
    executive_summary: Mapped[str | None] = mapped_column(Text)
    intel_verdict: Mapped[str | None] = mapped_column(String(32))
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assignee = relationship("User", back_populates="incidents", foreign_keys=[assignee_id])
    events = relationship("SecurityEvent", back_populates="incident")
    notes = relationship(
        "IncidentNote", back_populates="incident", cascade="all, delete-orphan",
        order_by="IncidentNote.created_at",
    )
    playbook_items = relationship(
        "PlaybookItem", back_populates="incident", cascade="all, delete-orphan",
        order_by="PlaybookItem.position",
    )
    runs = relationship(
        "AgentRun", back_populates="incident", cascade="all, delete-orphan",
        order_by="AgentRun.started_at",
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(24), default="note")  # note | status | system
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident = relationship("Incident", back_populates="notes")
    author = relationship("User", back_populates="notes")


class PlaybookItem(Base):
    __tablename__ = "playbook_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str] = mapped_column(String(32), default="containment")
    title: Mapped[str] = mapped_column(String(240))
    detail: Mapped[str] = mapped_column(Text, default="")
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    completed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    automatable: Mapped[bool] = mapped_column(Boolean, default=False)

    incident = relationship("Incident", back_populates="playbook_items")


# ---------------------------------------------------------------------------
# Agent orchestration
# ---------------------------------------------------------------------------
class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    trace_id: Mapped[str] = mapped_column(String(48), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued")  # queued|running|completed|failed
    triggered_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    trigger_reason: Mapped[str] = mapped_column(String(120), default="manual")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    final_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str | None] = mapped_column(String(48))
    error: Mapped[str | None] = mapped_column(Text)

    incident = relationship("Incident", back_populates="runs")
    steps = relationship(
        "AgentStep", back_populates="run", cascade="all, delete-orphan",
        order_by="AgentStep.position",
    )


class AgentStep(Base):
    __tablename__ = "agent_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    agent_key: Mapped[str] = mapped_column(String(48), index=True)
    agent_name: Mapped[str] = mapped_column(String(96))
    status: Mapped[str] = mapped_column(String(24), default="completed")
    headline: Mapped[str] = mapped_column(String(240), default="")
    reasoning: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[dict] = mapped_column(JSON, default=dict)
    rag_sources: Mapped[list] = mapped_column(JSON, default=list)
    tool_calls: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    model: Mapped[str] = mapped_column(String(64), default="sentinel-reasoner-v2")
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run = relationship("AgentRun", back_populates="steps")


# ---------------------------------------------------------------------------
# Knowledge base (RAG corpus)
# ---------------------------------------------------------------------------
class KnowledgeDoc(Base):
    __tablename__ = "knowledge_docs"

    id: Mapped[int] = mapped_column(primary_key=True)
    doc_key: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    category: Mapped[str] = mapped_column(String(48), index=True)  # mitre|playbook|cve|policy
    source: Mapped[str] = mapped_column(String(96), default="internal")
    technique_id: Mapped[str | None] = mapped_column(String(24), index=True)
    tactic: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(16))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    content: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------
class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[int] = mapped_column(primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), index=True)  # ISO27001 | SOC2
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    domain: Mapped[str] = mapped_column(String(96), default="")
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="compliant")  # compliant|partial|gap|na
    score: Mapped[int] = mapped_column(Integer, default=100)
    owner: Mapped[str] = mapped_column(String(96), default="Security Engineering")
    evidence: Mapped[str] = mapped_column(Text, default="")
    gap_notes: Mapped[str] = mapped_column(Text, default="")
    last_reviewed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("framework", "control_id", name="uq_framework_control"),)


# ---------------------------------------------------------------------------
# ML anomaly detection
# ---------------------------------------------------------------------------
class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("security_events.id"), index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    model_version: Mapped[str] = mapped_column(String(48), default="iforest-v1")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value)
    reason: Mapped[str] = mapped_column(Text, default="")
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="open")  # open|triaged|dismissed
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))


class ModelSnapshot(Base):
    __tablename__ = "model_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(48))
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    features: Mapped[list] = mapped_column(JSON, default=list)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)


# ---------------------------------------------------------------------------
# Threat intel cache (durable mirror of the Redis layer)
# ---------------------------------------------------------------------------
class IntelRecord(Base):
    __tablename__ = "intel_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(160), index=True)
    indicator_type: Mapped[str] = mapped_column(String(24))  # ip | hash | domain
    provider: Mapped[str] = mapped_column(String(32))  # virustotal | abuseipdb | heuristic
    verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    score: Mapped[int] = mapped_column(Integer, default=0)
    live: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("indicator", "provider", name="uq_indicator_provider"),)


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
class TraceSpan(Base):
    __tablename__ = "trace_spans"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(48), index=True)
    span_id: Mapped[str] = mapped_column(String(48), index=True)
    parent_span_id: Mapped[str | None] = mapped_column(String(48))
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24), default="llm")  # chain|llm|tool|retriever
    status: Mapped[str] = mapped_column(String(16), default="ok")
    model: Mapped[str | None] = mapped_column(String(64))
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    prompt_preview: Mapped[str] = mapped_column(Text, default="")
    output_preview: Mapped[str] = mapped_column(Text, default="")
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    exporter: Mapped[str] = mapped_column(String(24), default="local")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    actor_email: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(48), default="")
    target_id: Mapped[str] = mapped_column(String(48), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class CopilotMessage(Base):
    __tablename__ = "copilot_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_key: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[list] = mapped_column(JSON, default=list)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SavedHunt(Base):
    __tablename__ = "saved_hunts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    query: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    shared: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
