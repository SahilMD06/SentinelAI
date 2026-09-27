"""PDF report generation with reportlab.

Two report types:
  • Incident report  — case metadata, executive brief, full agent timeline,
                       playbook progress, correlated evidence.
  • Compliance report — framework scorecards and the open-gap register.

Output is deliberately plain: a print-ready document a compliance auditor can
file, not a screenshot of a dashboard.
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from ..models import Incident
from ..utils import as_utc

INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#CBD5E1")
ACCENT = colors.HexColor("#1D4ED8")
BG_SOFT = colors.HexColor("#F1F5F9")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#B91C1C"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#A16207"),
    "low": colors.HexColor("#0369A1"),
    "info": colors.HexColor("#475569"),
}
STATUS_COLORS = {
    "compliant": colors.HexColor("#15803D"),
    "partial": colors.HexColor("#A16207"),
    "gap": colors.HexColor("#B91C1C"),
    "na": MUTED,
}


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SATitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=19, leading=23, textColor=INK, alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "SASub", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "SAH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=12, leading=15, textColor=INK, spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "SAH3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=INK, spaceBefore=9, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "SABody", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=13, textColor=INK, spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "SASmall", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.6, leading=10.5, textColor=MUTED,
        ),
        "mono": ParagraphStyle(
            "SAMono", parent=base["Normal"], fontName="Courier",
            fontSize=7.4, leading=10, textColor=INK,
        ),
    }


class _Doc(BaseDocTemplate):
    def __init__(self, buffer, *, title: str, subtitle: str, classification: str):
        super().__init__(
            buffer, pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=20 * mm, bottomMargin=18 * mm,
            title=title, author="SentinelAI", subject=subtitle,
        )
        self.doc_title = title
        self.doc_subtitle = subtitle
        self.classification = classification
        frame = Frame(
            self.leftMargin, self.bottomMargin,
            self.width, self.height - 6 * mm, id="body",
        )
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._chrome)])

    def _chrome(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        # header rule + wordmark
        canvas.setFillColor(INK)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(18 * mm, h - 13 * mm, "SENTINELAI")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(38 * mm, h - 13 * mm, "· Security Operations Platform")
        canvas.drawRightString(w - 18 * mm, h - 13 * mm, self.classification)
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.6)
        canvas.line(18 * mm, h - 15.5 * mm, w - 18 * mm, h - 15.5 * mm)
        # footer
        canvas.line(18 * mm, 13 * mm, w - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(
            18 * mm, 9 * mm,
            f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC · {self.doc_title}",
        )
        canvas.drawRightString(w - 18 * mm, 9 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()


def _esc(text) -> str:
    return (
        str(text if text is not None else "—")
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _kv_table(rows: list[tuple[str, str]], styles: dict, col: float = 38 * mm) -> Table:
    data = [
        [Paragraph(f"<b>{_esc(k)}</b>", styles["small"]), Paragraph(_esc(v), styles["body"])]
        for k, v in rows
    ]
    table = Table(data, colWidths=[col, None], hAlign="LEFT")
    table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ])
    )
    return table


def _chip(text: str, color) -> Table:
    cell = Table([[Paragraph(
        f'<font color="#FFFFFF" size="7.5"><b>{_esc(text).upper()}</b></font>',
        ParagraphStyle("chip", fontName="Helvetica-Bold", fontSize=7.5, leading=10),
    )]], colWidths=[24 * mm])
    cell.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return cell


def _grid(data: list[list], widths: list, styles: dict, *, header: bool = True) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), BG_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK),
        ]
    table.setStyle(TableStyle(style))
    return table


def _markdown_to_flowables(md: str, styles: dict) -> list:
    """Minimal markdown renderer for the executive brief."""
    out = []
    for raw_line in (md or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            out.append(Spacer(1, 3))
            continue
        if line.startswith("### "):
            out.append(Paragraph(_esc(line[4:]), styles["h3"]))
        elif line.startswith("## "):
            out.append(Paragraph(_esc(line[3:]), styles["h2"]))
        elif line.startswith("- "):
            body = _bold(line[2:])
            out.append(Paragraph(f"• {body}", styles["body"]))
        else:
            out.append(Paragraph(_bold(line), styles["body"]))
    return out


def _bold(text: str) -> str:
    escaped = _esc(text)
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)


# ---------------------------------------------------------------------------
# Incident report
# ---------------------------------------------------------------------------
def incident_report(incident: Incident, *, generated_by: str = "SentinelAI") -> bytes:
    styles = _styles()
    buffer = io.BytesIO()
    doc = _Doc(
        buffer,
        title=f"Incident Report {incident.ref}",
        subtitle=incident.title,
        classification="CONFIDENTIAL · INTERNAL USE",
    )
    story: list = []

    story.append(Paragraph(f"{_esc(incident.ref)} — {_esc(incident.title)}", styles["title"]))
    story.append(Paragraph(
        f"Incident report generated by {_esc(generated_by)} · "
        f"{datetime.now(timezone.utc):%d %B %Y, %H:%M} UTC", styles["subtitle"]
    ))

    chips = Table(
        [[
            _chip(incident.severity, SEVERITY_COLORS.get(incident.severity, MUTED)),
            _chip(incident.priority, ACCENT),
            _chip(incident.status.replace("_", " "), colors.HexColor("#334155")),
            Paragraph(
                f'<font size="9"><b>Risk index {incident.risk_score}/100</b> · '
                f"confidence {incident.confidence}%</font>", styles["body"],
            ),
        ]],
        colWidths=[26 * mm, 26 * mm, 30 * mm, None], hAlign="LEFT",
    )
    chips.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    story.append(chips)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Case summary", styles["h2"]))
    story.append(_kv_table([
        ("Opened", f"{as_utc(incident.created_at):%Y-%m-%d %H:%M} UTC"),
        ("Last update", f"{as_utc(incident.updated_at):%Y-%m-%d %H:%M} UTC"),
        ("Category", incident.category),
        ("Detection source", incident.detection_source),
        ("Affected asset", f"{incident.asset} ({incident.asset_criticality} criticality)"),
        ("Source address", incident.src_ip or "internal"),
        ("Destination", incident.dest_ip or "—"),
        ("Affected principal", incident.affected_user or "—"),
        ("Kill-chain phase", incident.kill_chain_phase),
        ("ATT&CK techniques", ", ".join(incident.mitre_techniques or []) or "none mapped"),
        ("External reputation", incident.intel_verdict or "not assessed"),
        ("Assignee", incident.assignee.full_name if incident.assignee else "unassigned"),
        ("SLA due", f"{as_utc(incident.sla_due_at):%Y-%m-%d %H:%M} UTC" if incident.sla_due_at else "—"),
    ], styles))

    if incident.summary:
        story.append(Paragraph("Detection narrative", styles["h2"]))
        story.append(Paragraph(_esc(incident.summary), styles["body"]))

    if incident.executive_summary:
        story.append(Paragraph("Executive brief", styles["h2"]))
        story.extend(_markdown_to_flowables(incident.executive_summary, styles))

    if incident.root_cause:
        story.append(Paragraph("Root cause", styles["h2"]))
        story.append(Paragraph(_esc(incident.root_cause), styles["body"]))

    # -- agent timeline ----------------------------------------------------
    runs = sorted(incident.runs, key=lambda r: as_utc(r.started_at) or datetime.min.replace(tzinfo=timezone.utc))
    if runs:
        story.append(PageBreak())
        story.append(Paragraph("AI agent investigation timeline", styles["h2"]))
        latest = runs[-1]
        story.append(Paragraph(
            f"Trace <font face='Courier'>{_esc(latest.trace_id)}</font> · "
            f"{len(latest.steps)} agents · {latest.duration_ms} ms · "
            f"{latest.tokens_in + latest.tokens_out:,} tokens · "
            f"${latest.cost_usd:.4f} · triggered by {_esc(latest.trigger_reason)}",
            styles["small"],
        ))
        story.append(Spacer(1, 6))

        for step in sorted(latest.steps, key=lambda s: s.position):
            block = [
                Paragraph(
                    f"{step.position + 1}. {_esc(step.agent_name)} "
                    f"<font color='#64748B' size='8'>· {step.latency_ms} ms · "
                    f"{step.tokens_in + step.tokens_out:,} tokens · "
                    f"confidence {step.confidence}%</font>",
                    styles["h3"],
                ),
                Paragraph(f"<b>{_esc(step.headline)}</b>", styles["body"]),
            ]
            for line in (step.reasoning or "").splitlines():
                if line.strip():
                    block.append(Paragraph(_esc(line), styles["small"]))
            if step.rag_sources:
                cited = ", ".join(
                    f"{s.get('doc_key')} ({s.get('title', '')[:44]})" for s in step.rag_sources[:4]
                )
                block.append(Paragraph(f"<b>Knowledge cited:</b> {_esc(cited)}", styles["small"]))
            if step.tool_calls:
                tools = ", ".join(str(t.get("tool")) for t in step.tool_calls[:5])
                block.append(Paragraph(f"<b>Tools invoked:</b> {_esc(tools)}", styles["small"]))
            block.append(Spacer(1, 7))
            story.append(KeepTogether(block))

    # -- playbook ----------------------------------------------------------
    if incident.playbook_items:
        story.append(Paragraph("Mitigation playbook", styles["h2"]))
        done = sum(1 for i in incident.playbook_items if i.completed)
        story.append(Paragraph(
            f"{done} of {len(incident.playbook_items)} steps complete "
            f"({done * 100 // max(len(incident.playbook_items), 1)}%).", styles["small"]
        ))
        story.append(Spacer(1, 4))
        rows = [[
            Paragraph("<b>#</b>", styles["small"]),
            Paragraph("<b>Phase</b>", styles["small"]),
            Paragraph("<b>Action</b>", styles["small"]),
            Paragraph("<b>Status</b>", styles["small"]),
        ]]
        for item in sorted(incident.playbook_items, key=lambda i: i.position):
            rows.append([
                Paragraph(str(item.position + 1), styles["small"]),
                Paragraph(_esc(item.phase), styles["small"]),
                Paragraph(f"<b>{_esc(item.title)}</b><br/>{_esc(item.detail)}", styles["small"]),
                Paragraph(
                    "✓ complete" if item.completed else "open",
                    styles["small"],
                ),
            ])
        story.append(_grid(rows, [8 * mm, 24 * mm, None, 20 * mm], styles))

    # -- evidence ----------------------------------------------------------
    events = sorted(incident.events, key=lambda e: as_utc(e.ts) or datetime.min.replace(tzinfo=timezone.utc))[:40]
    if events:
        story.append(Paragraph("Correlated evidence", styles["h2"]))
        story.append(Paragraph(
            f"{len(incident.events)} event(s) correlated to this case; "
            f"showing the first {len(events)} chronologically.", styles["small"]
        ))
        story.append(Spacer(1, 4))
        rows = [[
            Paragraph("<b>Timestamp (UTC)</b>", styles["small"]),
            Paragraph("<b>Host</b>", styles["small"]),
            Paragraph("<b>Type</b>", styles["small"]),
            Paragraph("<b>Sev</b>", styles["small"]),
            Paragraph("<b>Message</b>", styles["small"]),
        ]]
        for ev in events:
            rows.append([
                Paragraph(f"{as_utc(ev.ts):%m-%d %H:%M:%S}", styles["mono"]),
                Paragraph(_esc(ev.host), styles["small"]),
                Paragraph(_esc(ev.event_type), styles["small"]),
                Paragraph(_esc(ev.severity), styles["small"]),
                Paragraph(_esc(ev.message[:180]), styles["mono"]),
            ])
        story.append(_grid(rows, [22 * mm, 24 * mm, 24 * mm, 14 * mm, None], styles))

    # -- notes -------------------------------------------------------------
    if incident.notes:
        story.append(Paragraph("Analyst notes and audit trail", styles["h2"]))
        for note in sorted(incident.notes, key=lambda n: as_utc(n.created_at) or datetime.min.replace(tzinfo=timezone.utc)):
            author = note.author.full_name if note.author else "System"
            story.append(Paragraph(
                f"<b>{_esc(author)}</b> · {as_utc(note.created_at):%Y-%m-%d %H:%M} UTC · "
                f"{_esc(note.kind)}", styles["small"]
            ))
            story.append(Paragraph(_esc(note.body), styles["body"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "This report was assembled from immutable case telemetry and the recorded agent "
        "reasoning trace. Retain per the evidence-retention schedule referenced in the "
        "compliance section of this case.", styles["small"]
    ))

    doc.build(story)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------
def compliance_report(
    controls: list, scores: list[dict], *, generated_by: str = "SentinelAI",
    framework: str | None = None,
) -> bytes:
    styles = _styles()
    buffer = io.BytesIO()
    label = framework or "ISO 27001 · SOC 2"
    doc = _Doc(
        buffer,
        title=f"Compliance Posture — {label}",
        subtitle="Control status and gap register",
        classification="CONFIDENTIAL · AUDIT EVIDENCE",
    )
    story: list = []

    story.append(Paragraph(f"Compliance posture — {_esc(label)}", styles["title"]))
    story.append(Paragraph(
        f"Generated by {_esc(generated_by)} · "
        f"{datetime.now(timezone.utc):%d %B %Y, %H:%M} UTC · "
        f"{len(controls)} controls in scope", styles["subtitle"]
    ))

    story.append(Paragraph("Framework scorecards", styles["h2"]))
    rows = [[
        Paragraph("<b>Framework</b>", styles["small"]),
        Paragraph("<b>Score</b>", styles["small"]),
        Paragraph("<b>Compliant</b>", styles["small"]),
        Paragraph("<b>Partial</b>", styles["small"]),
        Paragraph("<b>Gaps</b>", styles["small"]),
        Paragraph("<b>N/A</b>", styles["small"]),
        Paragraph("<b>Total</b>", styles["small"]),
    ]]
    for s in scores:
        rows.append([
            Paragraph(f"<b>{_esc(s['framework'])}</b>", styles["body"]),
            Paragraph(f"<b>{s['score']}%</b>", styles["body"]),
            Paragraph(str(s["compliant"]), styles["body"]),
            Paragraph(str(s["partial"]), styles["body"]),
            Paragraph(str(s["gaps"]), styles["body"]),
            Paragraph(str(s["not_applicable"]), styles["body"]),
            Paragraph(str(s["total"]), styles["body"]),
        ])
    story.append(_grid(rows, [40 * mm, 20 * mm, 22 * mm, 20 * mm, 18 * mm, 16 * mm, 18 * mm], styles))

    gaps = [c for c in controls if c.status in {"gap", "partial"}]
    story.append(Paragraph("Open gap register", styles["h2"]))
    if not gaps:
        story.append(Paragraph("No open gaps. All in-scope controls are assessed compliant.", styles["body"]))
    else:
        story.append(Paragraph(
            f"{len(gaps)} control(s) require remediation. Ordered by framework, then control ID.",
            styles["small"],
        ))
        story.append(Spacer(1, 4))
        rows = [[
            Paragraph("<b>Framework</b>", styles["small"]),
            Paragraph("<b>Control</b>", styles["small"]),
            Paragraph("<b>Title / finding</b>", styles["small"]),
            Paragraph("<b>Owner</b>", styles["small"]),
            Paragraph("<b>Status</b>", styles["small"]),
        ]]
        for c in sorted(gaps, key=lambda x: (x.framework, x.control_id)):
            rows.append([
                Paragraph(_esc(c.framework), styles["small"]),
                Paragraph(f"<b>{_esc(c.control_id)}</b>", styles["small"]),
                Paragraph(
                    f"<b>{_esc(c.title)}</b><br/>{_esc(c.gap_notes or c.description)}",
                    styles["small"],
                ),
                Paragraph(_esc(c.owner), styles["small"]),
                Paragraph(_esc(c.status), styles["small"]),
            ])
        story.append(_grid(rows, [22 * mm, 20 * mm, None, 30 * mm, 18 * mm], styles))

    story.append(PageBreak())
    story.append(Paragraph("Full control register", styles["h2"]))
    rows = [[
        Paragraph("<b>Framework</b>", styles["small"]),
        Paragraph("<b>Control</b>", styles["small"]),
        Paragraph("<b>Title</b>", styles["small"]),
        Paragraph("<b>Status</b>", styles["small"]),
        Paragraph("<b>Score</b>", styles["small"]),
        Paragraph("<b>Reviewed</b>", styles["small"]),
    ]]
    for c in sorted(controls, key=lambda x: (x.framework, x.control_id)):
        rows.append([
            Paragraph(_esc(c.framework), styles["small"]),
            Paragraph(_esc(c.control_id), styles["small"]),
            Paragraph(_esc(c.title), styles["small"]),
            Paragraph(_esc(c.status), styles["small"]),
            Paragraph(f"{c.score}%", styles["small"]),
            Paragraph(f"{as_utc(c.last_reviewed):%Y-%m-%d}", styles["small"]),
        ])
    story.append(_grid(rows, [22 * mm, 20 * mm, None, 20 * mm, 16 * mm, 22 * mm], styles))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Scores are computed as the mean control score within each framework, where compliant = "
        "100, partial = 55, gap = 0, and not-applicable controls are excluded from the mean.",
        styles["small"],
    ))

    doc.build(story)
    return buffer.getvalue()
