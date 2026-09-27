"""Agentic telemetry: spans, token accounting and latency for every agent hop.

Spans are always written to the SentinelAI trace store (which powers the
in-app Tracing panel). When LANGSMITH_API_KEY or a Phoenix collector endpoint
is configured the same spans are additionally forwarded to that platform, so
the built-in panel is a superset rather than a replacement.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import settings

log = logging.getLogger("sentinelai.tracing")

# Indicative pricing for the reasoning model, used for cost attribution.
COST_PER_1K_IN = 0.003
COST_PER_1K_OUT = 0.015


def new_trace_id() -> str:
    return uuid.uuid4().hex[:32]


def new_span_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class Span:
    trace_id: str
    span_id: str
    name: str
    kind: str = "llm"
    parent_span_id: str | None = None
    model: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    duration_ms: int = 0
    status: str = "ok"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    prompt_preview: str = ""
    output_preview: str = ""
    attributes: dict = field(default_factory=dict)

    @property
    def cost_usd(self) -> float:
        return round(
            (self.tokens_in / 1000) * COST_PER_1K_IN
            + (self.tokens_out / 1000) * COST_PER_1K_OUT,
            6,
        )


class _Exporter:
    """Optional forwarder to LangSmith / Phoenix."""

    def __init__(self) -> None:
        self.name = "local"
        self._client = None
        self._resolve()

    def _resolve(self) -> None:
        target = settings.tracing_exporter
        if target == "langsmith" and settings.langsmith_api_key:
            try:  # pragma: no cover - optional dependency
                from langsmith import Client

                self._client = Client(api_key=settings.langsmith_api_key)
                self.name = "langsmith"
                log.info("Tracing exporter: LangSmith (project=%s)", settings.tracing_project)
                return
            except Exception as exc:
                log.warning("LangSmith exporter unavailable: %s", exc)
        if target == "phoenix" and settings.phoenix_endpoint:
            try:  # pragma: no cover - optional dependency
                from phoenix.otel import register

                register(
                    project_name=settings.tracing_project,
                    endpoint=settings.phoenix_endpoint,
                )
                self.name = "phoenix"
                log.info("Tracing exporter: Phoenix (%s)", settings.phoenix_endpoint)
                return
            except Exception as exc:
                log.warning("Phoenix exporter unavailable: %s", exc)
        self.name = "local"

    def export(self, span: Span) -> None:
        if self.name == "langsmith" and self._client is not None:  # pragma: no cover
            try:
                self._client.create_run(
                    name=span.name,
                    run_type="llm" if span.kind == "llm" else "chain",
                    inputs={"prompt": span.prompt_preview},
                    outputs={"output": span.output_preview},
                    project_name=settings.tracing_project,
                    extra={"metadata": {**span.attributes, "trace_id": span.trace_id}},
                )
            except Exception as exc:
                log.debug("LangSmith export failed: %s", exc)


_exporter = _Exporter()
_buffer: list[Span] = []
_buffer_lock = threading.Lock()


def record(span: Span, *, persist: bool = True, collector: list | None = None) -> None:
    with _buffer_lock:
        _buffer.append(span)
        if len(_buffer) > settings.trace_buffer_size:
            del _buffer[: len(_buffer) - settings.trace_buffer_size]
    _exporter.export(span)
    if collector is not None:
        collector.append(span)
    if persist:
        _persist(span)


def span_row(span: Span):
    """Materialise a span as a TraceSpan ORM object (not yet added to a session)."""
    from ..models import TraceSpan

    return TraceSpan(
        trace_id=span.trace_id,
        span_id=span.span_id,
        parent_span_id=span.parent_span_id,
        name=span.name,
        kind=span.kind,
        status=span.status,
        model=span.model,
        tokens_in=span.tokens_in,
        tokens_out=span.tokens_out,
        cost_usd=span.cost_usd,
        duration_ms=span.duration_ms,
        started_at=span.started_at,
        prompt_preview=span.prompt_preview[:2_000],
        output_preview=span.output_preview[:2_000],
        attributes=span.attributes,
        exporter=_exporter.name,
    )


def persist_spans(db, spans: list[Span]) -> None:
    """Write spans through the caller's session.

    Callers that already hold a transaction MUST use this rather than letting
    a span open its own session: on SQLite a second writer blocks on the first
    one's lock, which turns a fast pipeline run into a multi-second stall per
    span.
    """
    for span in spans:
        db.add(span_row(span))


def _persist(span: Span) -> None:
    from ..database import session_scope

    try:
        with session_scope() as db:
            db.add(span_row(span))
    except Exception as exc:  # pragma: no cover - non-fatal
        log.debug("Span persistence skipped: %s", exc)


@contextmanager
def span(
    name: str,
    *,
    trace_id: str,
    kind: str = "llm",
    parent_span_id: str | None = None,
    model: str | None = "sentinel-reasoner-v2",
    attributes: dict | None = None,
    persist: bool = True,
    collector: list | None = None,
):
    s = Span(
        trace_id=trace_id,
        span_id=new_span_id(),
        parent_span_id=parent_span_id,
        name=name,
        kind=kind,
        model=model,
        attributes=attributes or {},
    )
    started = time.perf_counter()
    try:
        yield s
    except Exception as exc:
        s.status = "error"
        s.output_preview = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        s.duration_ms = int((time.perf_counter() - started) * 1000)
        record(s, persist=persist, collector=collector)


def estimate_tokens(text: str) -> int:
    """~4 characters per token is the standard rough heuristic."""
    return max(1, len(text) // 4)


def exporter_name() -> str:
    return _exporter.name


def status() -> dict:
    with _buffer_lock:
        buffered = len(_buffer)
    return {
        "exporter": _exporter.name,
        "configured_exporter": settings.tracing_exporter,
        "project": settings.tracing_project,
        "buffered_spans": buffered,
        "langsmith_key": bool(settings.langsmith_api_key),
        "phoenix_endpoint": bool(settings.phoenix_endpoint),
    }
