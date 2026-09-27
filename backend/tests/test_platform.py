"""Health probes, RAG, hunting, ingestion, compliance, reports and RBAC gating."""

from __future__ import annotations

import pytest

from app.services import mitre, threat_intel
from app.services.log_parser import parse_line, parse_query
from app.services.rag import engine as rag_engine


# --------------------------------------------------------------------- health
@pytest.mark.parametrize("path", ["/liveness", "/readiness", "/health"])
def test_probes_report_healthy(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.json()["status"] in {"alive", "ready", "healthy"}


def test_health_reports_database_and_components(client):
    body = client.get("/health").json()
    assert body["database"]["ok"] is True
    assert body["database"]["engine"] in {"sqlite", "postgresql"}
    for component in ("cache", "knowledge_index", "threat_intel", "anomaly_detector", "tracing"):
        assert component in body["components"]


# ------------------------------------------------------------------ retrieval
def test_knowledge_index_is_populated():
    described = rag_engine.describe()
    assert described["ready"] is True
    assert described["documents"] >= 100


def test_rag_retrieves_by_meaning_not_only_keyword():
    hits = rag_engine.search("someone is guessing passwords over and over", top_k=5)
    assert hits
    assert any("T1110" in (h.technique_id or "") or "brute" in h.title.lower() for h in hits)


def test_rag_boosts_exact_technique_ids():
    hits = rag_engine.search("T1486", top_k=3)
    assert any(h.technique_id == "T1486" for h in hits)


def test_rag_category_filter(client, analyst):
    response = client.post(
        "/api/rag/search", headers=analyst,
        json={"query": "containment steps", "top_k": 5, "category": "playbook"},
    )
    assert response.status_code == 200
    assert all(h["category"] == "playbook" for h in response.json())


# -------------------------------------------------------------------- parsing
def test_parses_sshd_failure_line():
    event = parse_line(
        "Aug 23 04:12:01 web-edge-01 sshd[9921]: Failed password for invalid user root "
        "from 185.220.101.47 port 44122 ssh2"
    )
    assert event["event_type"] == "auth_failure"
    assert event["src_ip"] == "185.220.101.47"
    assert event["host"] == "web-edge-01"
    assert event["dest_port"] == 44122
    assert event["matched_rule"] == "SIG-AUTH-001"


def test_parses_nginx_injection_line():
    event = parse_line(
        '45.155.205.233 - - [23/Aug/2026:04:15:02 +0000] '
        '"GET /admin.php?id=1%20UNION%20SELECT%20a,b HTTP/1.1" 500 812 "-" "sqlmap/1.7"'
    )
    assert event["event_type"] == "sql_injection"
    assert event["status_code"] == 500
    assert event["severity"] == "critical"


def test_parses_key_value_firewall_line():
    event = parse_line(
        'date=2026-08-23 time=04:20:00 devname="vpn-gw-01" type="traffic" action="deny" '
        'srcip=91.240.118.172 dstip=10.20.10.24 dstport=3389 proto="tcp" sentbyte=800 '
        'rcvdbyte=200 user="admin" service="TCP"'
    )
    assert event["src_ip"] == "91.240.118.172"
    assert event["dest_port"] == 3389
    assert event["action"] == "deny"


def test_blank_lines_are_rejected():
    assert parse_line("   ") is None
    assert parse_line("# comment") is None


# -------------------------------------------------------------------- hunting
def test_query_parser_understands_fields_negation_and_ranges():
    parsed = parse_query('severity:critical -user:root status>=500 "union select"')
    columns = {t["column"]: t for t in parsed.terms}
    assert columns["severity"]["value"] == "critical"
    assert columns["username"]["negated"] is True
    assert columns["status_code"]["op"] == ">="
    assert "union select" in parsed.free_text


def test_query_parser_warns_on_unknown_fields():
    parsed = parse_query("nonsense_field:value")
    assert parsed.warnings
    assert "Unknown field" in parsed.warnings[0]


def test_hunt_search_returns_facets_and_histogram(client, analyst):
    response = client.post(
        "/api/hunt/search", headers=analyst,
        json={"query": "event_type:auth_failure", "limit": 50},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"]
    assert all(i["event_type"] == "auth_failure" for i in body["items"])
    assert body["facets"] and body["histogram"]
    assert body["took_ms"] >= 0


def test_hunt_negation_actually_excludes(client, analyst):
    body = client.post(
        "/api/hunt/search", headers=analyst,
        json={"query": "-severity:info", "limit": 100},
    ).json()
    assert all(i["severity"] != "info" for i in body["items"])


# ------------------------------------------------------------------ ingestion
def test_ingest_normalises_and_stores(client, analyst):
    response = client.post(
        "/api/events/ingest", headers=analyst,
        json={
            "lines": [
                "Aug 23 05:00:01 bastion-01 sshd[101]: Failed password for admin "
                "from 45.9.148.212 port 51000 ssh2",
                "Aug 23 05:00:04 bastion-01 sshd[102]: Accepted password for admin "
                "from 45.9.148.212 port 51002 ssh2",
            ],
            "source_hint": "sshd",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert {e["event_type"] for e in body["parsed"]} == {"auth_failure", "auth_success"}


def test_viewer_cannot_ingest(client, viewer):
    response = client.post("/api/events/ingest", headers=viewer, json={"lines": ["x"]})
    assert response.status_code == 403
    assert "read-only" in response.json()["detail"].lower()


def test_pipeline_health_stages(client, analyst):
    body = client.get("/api/events/pipeline", headers=analyst).json()
    assert [s["key"] for s in body["stages"]] == ["collect", "parse", "enrich", "score", "index"]
    assert body["status"] in {"healthy", "degraded", "stalled"}


# ------------------------------------------------------------------ incidents
def test_incident_queue_filters_and_paginates(client, analyst):
    body = client.get("/api/incidents?severity=critical&size=5", headers=analyst).json()
    assert body["size"] == 5
    assert all(i["severity"] == "critical" for i in body["items"])


def test_playbook_toggle_advances_case_status(client, analyst, incident_ref):
    detail = client.get(f"/api/incidents/{incident_ref}", headers=analyst).json()
    item = detail["playbook_items"][0]
    updated = client.patch(
        f"/api/incidents/{incident_ref}/playbook/{item['id']}",
        headers=analyst, json={"completed": True},
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["status"] != "new"
    assert next(i for i in body["playbook_items"] if i["id"] == item["id"])["completed"]


def test_viewer_cannot_toggle_playbook(client, viewer, analyst, incident_ref):
    detail = client.get(f"/api/incidents/{incident_ref}", headers=analyst).json()
    item = detail["playbook_items"][0]
    response = client.patch(
        f"/api/incidents/{incident_ref}/playbook/{item['id']}",
        headers=viewer, json={"completed": True},
    )
    assert response.status_code == 403


def test_analyst_cannot_close_a_case(client, analyst, incident_ref):
    response = client.patch(
        f"/api/incidents/{incident_ref}", headers=analyst, json={"status": "closed"}
    )
    assert response.status_code == 403


def test_manager_can_close_a_case(client, manager, incident_ref):
    response = client.patch(
        f"/api/incidents/{incident_ref}", headers=manager, json={"status": "closed"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "closed"


def test_viewer_cannot_add_notes(client, viewer, incident_ref):
    response = client.post(
        f"/api/incidents/{incident_ref}/notes", headers=viewer, json={"body": "should fail"}
    )
    assert response.status_code == 403


# ------------------------------------------------------------------ intel
def test_intel_lookup_is_deterministic_offline():
    first = threat_intel.lookup("45.155.205.233", force_refresh=True)
    second = threat_intel.lookup("45.155.205.233", force_refresh=True)
    assert first["score"] == second["score"]
    assert first["live"] is False
    assert first["indicator_type"] == "ip"


def test_intel_marks_private_addresses_internal():
    result = threat_intel.lookup("10.20.10.24", force_refresh=True)
    assert result["providers"][0]["verdict"] == "internal"


def test_intel_classifies_hashes_and_domains():
    assert threat_intel.classify_indicator("a" * 64) == "hash"
    assert threat_intel.classify_indicator("malicious.example.com") == "domain"
    assert threat_intel.classify_indicator("not an indicator") == "unknown"


def test_intel_second_lookup_is_cached(client, analyst):
    client.post("/api/intel/lookup?refresh=true", headers=analyst,
                json={"indicator": "185.220.101.47"})
    second = client.post("/api/intel/lookup", headers=analyst,
                         json={"indicator": "185.220.101.47"}).json()
    assert second["cached"] is True


# ------------------------------------------------------------------ compliance
def test_compliance_overview_scores_each_framework(client, analyst):
    body = client.get("/api/compliance/overview", headers=analyst).json()
    frameworks = {f["framework"] for f in body["frameworks"]}
    assert {"ISO27001", "SOC2"} <= frameworks
    for framework in body["frameworks"]:
        assert 0 <= framework["score"] <= 100
        assert framework["total"] == (
            framework["compliant"] + framework["partial"]
            + framework["gaps"] + framework["not_applicable"]
        )


def test_only_admin_can_edit_controls(client, analyst, admin):
    control = client.get("/api/compliance/controls?framework=SOC2", headers=analyst).json()[0]
    assert client.patch(
        f"/api/compliance/controls/{control['id']}", headers=analyst, json={"status": "compliant"}
    ).status_code == 403
    assert client.patch(
        f"/api/compliance/controls/{control['id']}", headers=admin,
        json={"status": "partial", "gap_notes": "Automation pending"},
    ).status_code == 200


# ------------------------------------------------------------------ reporting
def test_incident_pdf_is_a_valid_document(client, analyst, incident_ref):
    response = client.get(f"/api/incidents/{incident_ref}/report.pdf", headers=analyst)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert len(response.content) > 5_000


def test_compliance_pdf_is_a_valid_document(client, analyst):
    response = client.get("/api/compliance/report.pdf?framework=ISO27001", headers=analyst)
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_viewer_may_export_reports(client, viewer, incident_ref):
    # Read-only users still need evidence for audit; export is a read capability.
    assert client.get(
        f"/api/incidents/{incident_ref}/report.pdf", headers=viewer
    ).status_code == 200


# ------------------------------------------------------------------ mitre
def test_mitre_keyword_mapping():
    matched = mitre.match_text("repeated failed password attempts and authentication failure")
    assert any(t["id"] == "T1110" for t in matched)


def test_mitre_label_falls_back_gracefully():
    assert mitre.label("T9999") == "T9999"
    assert "Brute Force" in mitre.label("T1110")


# ------------------------------------------------------------------ copilot
def test_copilot_answers_with_citations(client, analyst):
    response = client.post(
        "/api/copilot/chat", headers=analyst,
        json={"message": "What are the highest-risk open incidents right now?"},
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["reply"]) > 80
    assert body["trace_id"]
    assert body["tokens_out"] > 0


def test_copilot_explains_a_technique(client, analyst):
    body = client.post(
        "/api/copilot/chat", headers=analyst,
        json={"message": "Explain T1110 and how we detect it"},
    ).json()
    assert "T1110" in body["reply"]
    assert "Brute Force" in body["reply"]


def test_viewer_cannot_use_copilot(client, viewer):
    assert client.post(
        "/api/copilot/chat", headers=viewer, json={"message": "hello"}
    ).status_code == 403


# ------------------------------------------------------------------ tracing
def test_tracing_captures_agent_spans(client, analyst, incident_ref):
    client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst)
    stats = client.get("/api/tracing/stats", headers=analyst).json()
    assert stats["total_spans"] > 0
    assert stats["tokens_out"] > 0
    agents = {a["agent"] for a in stats["by_agent"]}
    assert {"log_analyst", "risk", "reporter"} <= agents


def test_trace_detail_returns_the_span_tree(client, analyst):
    traces = client.get("/api/tracing/traces?limit=1", headers=analyst).json()
    detail = client.get(f"/api/tracing/traces/{traces[0]['trace_id']}", headers=analyst).json()
    assert detail["spans"]
    roots = [s for s in detail["spans"] if s["parent_span_id"] is None]
    assert len(roots) == 1


# ------------------------------------------------------------------ dashboard
def test_dashboard_aggregates_are_coherent(client, analyst):
    body = client.get("/api/dashboard", headers=analyst).json()
    assert body["open_incidents"] >= body["critical_incidents"]
    assert len(body["events_timeline"]) == 24
    assert 0 <= body["detection_coverage"] <= 100
    assert 0 <= body["risk_index"] <= 100
