import json
import shutil

import pytest

from caziel import analysis, cloud

from .conftest import FLEET


def checks(report, actor):
    return {f.check for f in report.result(actor).findings}


def test_prompt_injected_agent(report):
    r = report.result("agent:dispatch-agent")
    assert checks(report, "agent:dispatch-agent") == {"CZL-001", "CZL-003", "CZL-006", "CZL-008", "CZL-010"}
    assert len(r.moving_robots) == 12
    assert r.contact["base"][0] == pytest.approx(2.0)
    assert r.severity == "critical"


def test_scoped_supervisor_role_is_safe(report):
    r = report.result("principal:site-supervisor-role")
    assert r.moving_robots == ["kx1-01", "kx1-02", "kx1-03", "kx1-04"]
    assert r.findings == []
    assert r.worst_ratio()[0] == 0


def test_read_only_roles_reach_nothing(report):
    for key in ("principal:telemetry-analytics-role", "agent:inventory-agent", "principal:dispatch-agent-role"):
        assert report.result(key).robots == []


def test_ops_console_escalates_through_agent_and_lambda(report):
    r = report.result("principal:ops-console-role")
    assert "CZL-007" in checks(report, "principal:ops-console-role")
    assert any("rewrites Lambda fleet-nudge" in e for e in r.escalations)
    assert any("invokes agent dispatch-agent" in e for e in r.escalations)
    # lifecycle and raw arm come from the tool role it can hijack, not its own policy
    assert {"CZL-002", "CZL-004"} <= checks(report, "principal:ops-console-role")


def test_vendor_key_runs_code_through_jobs(report):
    r = report.result("principal:vendor-support")
    assert "CZL-005" in checks(report, "principal:vendor-support")
    assert "iot:CreateJob" in r.reach["kx1-01"].code_exec


def test_release_pipeline_deploys_via_greengrass(report):
    r = report.result("principal:release-pipeline-role")
    assert "greengrass:CreateDeployment" in r.reach["kx1-05"].code_exec


def test_network_finding(report):
    (f,) = report.network
    assert f.check == "CZL-009" and f.robots == 12


def test_counts_and_order(report):
    c = report.counts()
    assert c["critical"] > 0 and c["high"] > 0
    sevs = [r.severity for r in report.results]
    assert sevs[0] == "critical" and sevs[-1] == "info"


def test_accepted_risks_are_not_counted(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    p = d / "fleet.yaml"
    p.write_text(
        p.read_text() + "\naccepted_risks:\n  - actor: network:kx1\n    check: CZL-009\n    reason: lab only\n"
    )
    rep = analysis.analyze(cloud.load(d))
    (f,) = rep.network
    assert f.accepted == "lab only"
    assert f not in rep.open_findings


def test_human_approval_gates_the_agent(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    p = d / "cloud" / "agents.yaml"
    p.write_text(p.read_text().replace("human_approval: false", "human_approval: true", 1))
    rep = analysis.analyze(cloud.load(d))
    r = rep.result("agent:dispatch-agent")
    assert r.worst_ratio()[0] == 0
    assert "CZL-006" not in {f.check for f in r.findings}


def test_non_shell_jobs_are_not_code_execution(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    p = d / "fleet.yaml"
    p.write_text(p.read_text().replace("handler: shell", "handler: signed-documents"))
    rep = analysis.analyze(cloud.load(d))
    assert "CZL-005" not in {f.check for f in rep.result("principal:vendor-support").findings}


def test_load_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        cloud.load(tmp_path)
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    p = d / "cloud" / "agents.yaml"
    p.write_text(p.read_text().replace("role: fleet-tools-role", "role: ghost-role", 1))
    with pytest.raises(ValueError):
        cloud.load(d)
    shutil.rmtree(d)
    shutil.copytree(FLEET, d)
    p = d / "fleet.yaml"
    p.write_text(p.read_text().replace("thigh]", "tail]"))
    with pytest.raises(ValueError):
        cloud.load(d)


def test_explicit_thing_list(tmp_path):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    p = d / "fleet.yaml"
    p.write_text(p.read_text().replace("things: {prefix: kx1-, count: 12}", "things: [kx1-01, kx1-02]"))
    assert cloud.load(d).thing_count == 2
    with pytest.raises(ValueError):
        cloud._things(7)


def test_finding_dict(report):
    d = report.findings[0].to_dict()
    assert d["severity"] == "critical" and d["attack"] and d["fix"]
    json.dumps(d)
