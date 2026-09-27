"""Agent orchestration pipeline behaviour."""

from __future__ import annotations

from app.services.agent_pipeline import AGENTS, build_threat_chain


def test_pipeline_declares_nine_agents():
    assert len(AGENTS) == 9
    keys = [a[0] for a in AGENTS]
    assert keys == [
        "log_analyst", "threat_intel", "correlation", "risk", "mitre",
        "root_cause", "recommendation", "compliance", "reporter",
    ]


def test_investigation_produces_a_full_ordered_timeline(client, analyst, incident_ref):
    response = client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst)
    assert response.status_code == 200
    run = response.json()

    assert run["status"].startswith("completed")
    assert len(run["steps"]) == 9
    assert [s["position"] for s in run["steps"]] == list(range(9))
    assert all(s["status"] == "completed" for s in run["steps"])

    # Every step must carry auditable substance, not just a label.
    for step in run["steps"]:
        assert step["headline"], f"{step['agent_key']} produced no headline"
        assert len(step["reasoning"]) > 40, f"{step['agent_key']} reasoning too thin"
        assert step["latency_ms"] >= 0
        assert step["tokens_in"] > 0 and step["tokens_out"] > 0

    assert run["tokens_in"] == sum(s["tokens_in"] for s in run["steps"])
    assert run["tokens_out"] == sum(s["tokens_out"] for s in run["steps"])
    assert run["cost_usd"] > 0
    assert run["trace_id"]


def test_agents_share_state_downstream(client, analyst, incident_ref):
    run = client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst).json()
    steps = {s["agent_key"]: s for s in run["steps"]}

    # Risk scoring must consume the threat-intel verdict produced two steps earlier.
    intel_score = steps["threat_intel"]["findings"]["max_score"]
    components = {c["name"]: c["value"] for c in steps["risk"]["findings"]["components"]}
    assert components["External reputation"] == round(intel_score * 0.22, 1)

    # The reporter must inherit the mapped techniques rather than re-deriving them.
    techniques = steps["mitre"]["findings"]["techniques"]
    markdown = steps["reporter"]["findings"]["markdown"]
    if techniques:
        assert techniques[0] in markdown


def test_risk_score_is_bounded_and_drives_severity(client, analyst, incident_ref):
    run = client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst).json()
    risk = next(s for s in run["steps"] if s["agent_key"] == "risk")["findings"]
    assert 0 <= risk["risk_score"] <= 100
    expected = (
        "critical" if risk["risk_score"] >= 80 else
        "high" if risk["risk_score"] >= 60 else
        "medium" if risk["risk_score"] >= 35 else "low"
    )
    assert risk["severity"] == expected


def test_investigation_writes_back_to_the_case(client, analyst, incident_ref):
    run = client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst).json()
    detail = client.get(f"/api/incidents/{incident_ref}", headers=analyst).json()
    assert detail["risk_score"] == run["final_risk_score"]
    assert detail["executive_summary"]
    assert detail["root_cause"]
    assert detail["playbook_key"]


def test_agents_cite_knowledge_base_sources(client, analyst, incident_ref):
    run = client.post(f"/api/incidents/{incident_ref}/investigate", headers=analyst).json()
    cited = sum(len(s["rag_sources"]) for s in run["steps"])
    assert cited > 0, "no agent retrieved supporting documentation"


def test_viewer_cannot_trigger_agents(client, viewer, incident_ref):
    assert client.post(f"/api/incidents/{incident_ref}/investigate", headers=viewer).status_code == 403


def test_threat_chain_is_a_connected_graph(client, analyst, incident_ref):
    chain = client.get(f"/api/incidents/{incident_ref}/threat-chain", headers=analyst).json()
    ids = {n["id"] for n in chain["nodes"]}
    assert "src" in ids and "impact" in ids
    for edge in chain["edges"]:
        assert edge["source"] in ids and edge["target"] in ids


def test_build_threat_chain_handles_a_bare_incident():
    class Bare:
        src_ip = None
        intel_verdict = None
        root_cause = None
        kill_chain_phase = "reconnaissance"
        category = "reconnaissance"
        mitre_techniques: list = []
        asset = "unknown"
        asset_criticality = "low"
        risk_score = 0

    chain = build_threat_chain(Bare(), [])
    assert chain["nodes"] and chain["edges"]


def test_simulation_is_admin_only_and_runs_the_pipeline(client, admin, viewer):
    assert client.post(
        "/api/incidents/simulate", headers=viewer, json={"scenario": "random"}
    ).status_code == 403

    response = client.post(
        "/api/incidents/simulate", headers=admin,
        json={"scenario": "bruteforce-ssh", "run_agents": True},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["ref"].startswith("SIM-")
    assert body["runs"] and len(body["runs"][0]["steps"]) == 9
    assert body["events"]
