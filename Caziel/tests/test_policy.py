import json
import xml.etree.ElementTree as ET

import pytest
import yaml

from caziel import analysis, cloud, policy

from .conftest import FLEET


@pytest.fixture(scope="module")
def fixed(tmp_path_factory):
    out = tmp_path_factory.mktemp("fix") / "hardened"
    plan, before, after = policy.fix(FLEET, out)
    return out, plan, before, after


def test_hardened_fleet_rescans_clean(fixed):
    out, plan, _before, after = fixed
    assert plan.changes
    rescan = analysis.analyze(cloud.load(out))
    assert rescan.counts() == after.counts()
    assert after.counts()["critical"] == 0
    for check in ("CZL-001", "CZL-002", "CZL-003", "CZL-004", "CZL-006", "CZL-009"):
        assert not any(f.check == check for f in after.open_findings), check


def test_agent_can_still_work_but_not_hurt(fixed):
    _, _, before, after = fixed
    b, a = before.result("agent:dispatch-agent"), after.result("agent:dispatch-agent")
    assert b.worst_ratio()[0] > 10
    assert a.worst_ratio()[0] == 0
    assert len(a.moving_robots) == 12  # navigation still works


def test_nudge_is_retargeted_not_removed(fixed):
    out, *_ = fixed
    bridge = yaml.safe_load((out / "robots/kx1/bridge.yaml").read_text())
    vel = next(m for m in bridge["mappings"] if m["mqtt"].endswith("/velocity"))
    assert vel["ros"]["name"] == "/cmd_vel_smoothed" and vel["requires_approval"]
    kinds = {m["ros"]["kind"] for m in bridge["mappings"]}
    assert "parameters" not in kinds
    assert not any(m["mqtt"].endswith("/arm") for m in bridge["mappings"])
    life = next(m for m in bridge["mappings"] if m["ros"]["kind"] == "lifecycle")
    assert "/collision_monitor" not in life["ros"]["nodes"]
    assert bridge["lan"] == {"endpoint": "127.0.0.1:9090", "auth": "token"}


def test_speed_caps_follow_the_physics(fixed):
    out, *_ = fixed
    fleet = cloud.load(FLEET)
    v, region = policy.safe_base_speed(fleet, fleet.groups[0].model)
    assert region == "thigh" and v == pytest.approx(0.29, abs=0.01)
    params = yaml.safe_load((out / "robots/kx1/params.yaml").read_text())
    assert params["velocity_smoother"]["ros__parameters"]["max_velocity"][0] == 0.25
    assert params["controller_server"]["ros__parameters"]["FollowPath"]["max_vel_x"] == 0.25
    scale, _ = policy.safe_arm_scaling(fleet, fleet.groups[0].model)
    assert scale > 0.1  # MoveIt's 0.1 was already safe, so it is left alone


def test_release_pipeline_is_accepted_not_silenced(fixed):
    out, plan, _, after = fixed
    r = after.result("principal:release-pipeline-role")
    assert r.findings and all(f.accepted for f in r.findings)
    assert any("release-pipeline-role" in m for m in plan.manual)
    cfg = yaml.safe_load((out / "fleet.yaml").read_text())
    assert cfg["accepted_risks"][0]["actor"] == "principal:release-pipeline-role"
    assert cfg["iot"]["jobs"]["handler"] == "signed-documents"


def test_iam_guardrails(fixed):
    out, *_ = fixed
    principals = {p["name"]: p for p in json.loads((out / "cloud/iam.json").read_text())["principals"]}
    sids = [s["Sid"] for d in principals["vendor-support"]["policies"] for s in d["Statement"]]
    assert "CazielFleetGuardrailCode" in sids
    tool = next(
        s for d in principals["fleet-tools-role"]["policies"] for s in d["Statement"] if s["Sid"] == "CazielToolScope"
    )
    assert all("cmd/param" not in r for r in tool["NotResource"])
    assert (
        principals["site-supervisor-role"]["policies"]
        == json.loads((FLEET / "cloud/iam.json").read_text())["principals"][5]["policies"]
    )


def test_agent_tool_removed(fixed):
    out, *_ = fixed
    agents = yaml.safe_load((out / "cloud/agents.yaml").read_text())["agents"]
    tools = [t["name"] for t in agents[0]["tools"]]
    assert "tune_speed" not in tools and "nudge" in tools


def test_artifacts(fixed):
    out, *_ = fixed
    xml = ET.fromstring((out / "caziel-fix/sros2/kx1.policy.xml").read_text())
    denied = [e.text for e in xml.iter("service") if e.text and "collision_monitor" in e.text]
    assert "collision_monitor/change_state" in denied
    scp = json.loads((out / "caziel-fix/scp-fleet-guardrail.json").read_text())
    assert scp["Statement"][-1]["Condition"]["ArnNotLike"]["aws:PrincipalArn"][0].endswith("release-pipeline-role")
    changes = (out / "caziel-fix/CHANGES.md").read_text()
    assert "Before and after" in changes and "12 → 0" in changes
    graph = json.loads((out / "robots/kx1/graph.json").read_text())
    assert graph["environment"]["ROS_SECURITY_ENABLE"] == "true" and "projected_by" in graph


def test_refuses_to_clobber_unrelated_directory(tmp_path):
    victim = tmp_path / "home"
    victim.mkdir()
    (victim / "notes.txt").write_text("keep me")
    with pytest.raises(FileExistsError):
        policy.fix(FLEET, victim)
    assert (victim / "notes.txt").exists()


def test_fix_is_idempotent(fixed, tmp_path):
    out, *_ = fixed
    plan, before, after = policy.fix(out, tmp_path / "again")
    assert not any(c.area == "bridge" and c.what == "Removed" for c in plan.changes)
    assert after.counts() == before.counts()


def test_attack_path_reports_the_block(fixed):
    from caziel import report

    _, _, before, after = fixed
    a = after.result("agent:dispatch-agent")
    steps = report.attack_path(after.fleet, a, "base")
    assert steps[-1]["layer"] == "blocked" and "approve" in steps[-1]["text"]
    b = before.result("agent:dispatch-agent")
    assert report.attack_path(before.fleet, b, "base")[-1]["layer"] == "physical"
    assert report.attack_path(before.fleet, before.result("principal:telemetry-analytics-role")) == []
