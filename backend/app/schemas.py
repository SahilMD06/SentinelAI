"""Pydantic request/response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

ORM = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- auth
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ORM
    id: int
    email: EmailStr
    full_name: str
    role: str
    job_title: str
    team: str
    is_active: bool
    auth_provider: str
    mfa_enrolled: bool
    last_login_at: datetime | None = None
    created_at: datetime


class SessionOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: datetime
    user: UserOut
    role_label: str
    capabilities: list[str]


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "manager", "analyst", "viewer"] = "viewer"
    job_title: str = "Security Staff"
    team: str = "SOC"
    is_active: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=160)
    role: Literal["admin", "manager", "analyst", "viewer"] | None = None
    job_title: str | None = None
    team: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


# ---------------------------------------------------------------- events
class EventOut(BaseModel):
    model_config = ORM
    id: int
    ts: datetime
    source: str
    host: str
    src_ip: str | None
    dest_ip: str | None
    dest_port: int | None
    protocol: str | None
    username: str | None
    event_type: str
    severity: str
    action: str | None
    status_code: int | None
    bytes_out: int
    bytes_in: int
    geo_country: str | None
    matched_rule: str | None
    message: str
    raw: str
    is_anomaly: bool
    anomaly_score: float
    incident_id: int | None


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    page: int
    size: int


class EventIngest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=5_000)
    source_hint: str | None = None


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    parsed: list[EventOut]
    errors: list[str]


# ---------------------------------------------------------------- incidents
class NoteOut(BaseModel):
    model_config = ORM
    id: int
    body: str
    kind: str
    created_at: datetime
    author_name: str | None = None


class PlaybookItemOut(BaseModel):
    model_config = ORM
    id: int
    position: int
    phase: str
    title: str
    detail: str
    completed: bool
    completed_at: datetime | None
    completed_by: str | None = None
    automatable: bool


class AgentStepOut(BaseModel):
    model_config = ORM
    id: int
    position: int
    agent_key: str
    agent_name: str
    status: str
    headline: str
    reasoning: str
    findings: dict[str, Any]
    rag_sources: list[Any]
    tool_calls: list[Any]
    confidence: int
    model: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    started_at: datetime
    finished_at: datetime | None


class AgentRunOut(BaseModel):
    model_config = ORM
    id: int
    incident_id: int
    trace_id: str
    status: str
    trigger_reason: str
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    final_risk_score: int
    verdict: str | None
    error: str | None
    steps: list[AgentStepOut] = []


class IncidentSummary(BaseModel):
    model_config = ORM
    id: int
    ref: str
    title: str
    severity: str
    status: str
    priority: str
    risk_score: int
    category: str
    asset: str
    src_ip: str | None
    detection_source: str
    mitre_techniques: list[Any]
    tags: list[Any]
    created_at: datetime
    updated_at: datetime
    sla_due_at: datetime | None
    assignee_name: str | None = None
    open_tasks: int = 0
    total_tasks: int = 0


class ThreatChainNode(BaseModel):
    id: str
    label: str
    sublabel: str = ""
    kind: str  # source | vector | asset | impact | control


class ThreatChainEdge(BaseModel):
    source: str
    target: str
    label: str = ""


class ThreatChain(BaseModel):
    nodes: list[ThreatChainNode]
    edges: list[ThreatChainEdge]


class IncidentDetail(IncidentSummary):
    summary: str
    confidence: int
    asset_criticality: str
    dest_ip: str | None
    affected_user: str | None
    kill_chain_phase: str
    playbook_key: str | None
    root_cause: str | None
    executive_summary: str | None
    intel_verdict: str | None
    closed_at: datetime | None
    notes: list[NoteOut] = []
    playbook_items: list[PlaybookItemOut] = []
    runs: list[AgentRunOut] = []
    events: list[EventOut] = []
    threat_chain: ThreatChain | None = None


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    total: int
    page: int
    size: int


class IncidentUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    priority: str | None = None
    assignee_id: int | None = None
    tags: list[str] | None = None


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4_000)


class PlaybookToggle(BaseModel):
    completed: bool


class SimulationRequest(BaseModel):
    scenario: Literal[
        "bruteforce-ssh", "credential-stuffing", "web-shell", "data-exfiltration",
        "ransomware-precursor", "privilege-escalation", "dns-tunnelling", "random",
    ] = "random"
    run_agents: bool = True


# ---------------------------------------------------------------- hunting
class HuntRequest(BaseModel):
    query: str = ""
    start: datetime | None = None
    end: datetime | None = None
    limit: int = Field(default=200, ge=1, le=2_000)


class HuntFacet(BaseModel):
    field: str
    values: list[dict[str, Any]]


class HuntResponse(BaseModel):
    items: list[EventOut]
    total: int
    took_ms: int
    parsed_filters: dict[str, Any]
    facets: list[HuntFacet]
    histogram: list[dict[str, Any]]
    warnings: list[str] = []


class SavedHuntIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    query: str


class SavedHuntOut(BaseModel):
    model_config = ORM
    id: int
    name: str
    query: str
    shared: bool
    created_at: datetime


# ---------------------------------------------------------------- RAG / copilot
class RagHit(BaseModel):
    doc_key: str
    title: str
    category: str
    technique_id: str | None = None
    score: float
    snippet: str


class RagQuery(BaseModel):
    query: str = Field(min_length=2, max_length=1_000)
    top_k: int = Field(default=5, ge=1, le=20)
    category: str | None = None


class CopilotRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4_000)
    session_key: str = "default"
    incident_ref: str | None = None


class CopilotReply(BaseModel):
    reply: str
    citations: list[RagHit]
    latency_ms: int
    tokens_in: int
    tokens_out: int
    trace_id: str


# ---------------------------------------------------------------- compliance
class ControlOut(BaseModel):
    model_config = ORM
    id: int
    framework: str
    control_id: str
    domain: str
    title: str
    description: str
    status: str
    score: int
    owner: str
    evidence: str
    gap_notes: str
    last_reviewed: datetime


class FrameworkScore(BaseModel):
    framework: str
    score: int
    compliant: int
    partial: int
    gaps: int
    not_applicable: int
    total: int


class ComplianceOverview(BaseModel):
    frameworks: list[FrameworkScore]
    open_gaps: list[ControlOut]
    generated_at: datetime


class ControlUpdate(BaseModel):
    status: Literal["compliant", "partial", "gap", "na"] | None = None
    evidence: str | None = None
    gap_notes: str | None = None
    owner: str | None = None


# ---------------------------------------------------------------- intel
class IntelRequest(BaseModel):
    indicator: str = Field(min_length=3, max_length=160)


class IntelOut(BaseModel):
    indicator: str
    indicator_type: str
    verdict: str
    score: int
    providers: list[dict[str, Any]]
    live: bool
    cached: bool
    cache_backend: str
    fetched_at: datetime
    expires_at: datetime | None


# ---------------------------------------------------------------- anomalies
class AnomalyOut(BaseModel):
    model_config = ORM
    id: int
    event_id: int | None
    detected_at: datetime
    model_version: str
    score: float
    severity: str
    reason: str
    features: dict[str, Any]
    status: str
    incident_id: int | None


class ModelSnapshotOut(BaseModel):
    model_config = ORM
    id: int
    name: str
    version: str
    trained_at: datetime
    samples: int
    features: list[Any]
    metrics: dict[str, Any]
    duration_ms: int


# ---------------------------------------------------------------- tracing
class SpanOut(BaseModel):
    model_config = ORM
    id: int
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: str
    status: str
    model: str | None
    tokens_in: int
    tokens_out: int
    cost_usd: float
    duration_ms: int
    started_at: datetime
    prompt_preview: str
    output_preview: str
    attributes: dict[str, Any]
    exporter: str


class TraceSummary(BaseModel):
    trace_id: str
    root_name: str
    started_at: datetime
    duration_ms: int
    spans: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    status: str


class TracingStats(BaseModel):
    exporter: str
    project: str
    total_traces: int
    total_spans: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    p50_ms: int
    p95_ms: int
    by_agent: list[dict[str, Any]]


# ---------------------------------------------------------------- dashboard
class MetricPoint(BaseModel):
    label: str
    value: float


class DashboardOut(BaseModel):
    open_incidents: int
    critical_incidents: int
    events_24h: int
    anomalies_open: int
    mttr_minutes: int
    detection_coverage: int
    risk_index: int
    severity_breakdown: list[MetricPoint]
    status_breakdown: list[MetricPoint]
    events_timeline: list[MetricPoint]
    top_sources: list[MetricPoint]
    top_techniques: list[dict[str, Any]]
    pipeline: dict[str, Any]
    recent_incidents: list[IncidentSummary]


class PipelineHealth(BaseModel):
    stages: list[dict[str, Any]]
    ingest_rate_per_min: float
    queue_depth: int
    lag_seconds: float
    dropped_24h: int
    status: str
    updated_at: datetime


# ---------------------------------------------------------------- system
class HealthOut(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    database: dict[str, Any]
    components: dict[str, Any]
    uptime_seconds: float
    timestamp: datetime


class AuditOut(BaseModel):
    model_config = ORM
    id: int
    actor_email: str
    action: str
    target_type: str
    target_id: str
    detail: str
    ip: str | None
    created_at: datetime
