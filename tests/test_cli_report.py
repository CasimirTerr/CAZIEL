import json

import pytest

from caziel import cli, report, snapshot

from .conftest import FLEET, KX1


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_scan_text(capsys):
    code, out, _ = run(capsys, "scan", str(FLEET), "--no-color")
    assert code == 0
    assert "Who can move your robots" in out and "Worst attack path" in out
    assert "\033[" not in out


def test_scan_color_when_forced():
    from caziel import analysis, cloud

    text = report.to_text(analysis.analyze(cloud.load(FLEET)), color=True)
    assert "\033[1;31m" in text


def test_scan_json_and_fail_on(capsys, tmp_path):
    out = tmp_path / "r.json"
    code, _, err = run(capsys, "scan", str(FLEET), "-f", "json", "-o", str(out), "--fail-on", "critical")
    assert code == 2 and "open finding" in err
    data = json.loads(out.read_text())
    assert data["fleet"]["robots"] == 12
    assert data["summary"]["worst"]["actor"]
    actor = next(a for a in data["actors"] if a["key"] == "agent:dispatch-agent")
    assert actor["attack_path"][0]["layer"] == "entry"
    assert actor["attack_path"][-1]["layer"] == "physical"


def test_scan_markdown(capsys):
    code, out, _ = run(capsys, "scan", str(FLEET), "-f", "md")
    assert code == 0 and out.startswith("# Caziel report")
    assert "## Worst attack path" in out


def test_fix_command(capsys, tmp_path):
    code, out, _ = run(capsys, "fix", str(FLEET), "-o", str(tmp_path / "h"))
    assert code == 0 and "Still to do by hand" in out
    code, out, _ = run(capsys, "scan", str(tmp_path / "h"), "--fail-on", "critical")
    assert code == 0


def test_robot_and_checks(capsys):
    _code, out, _ = run(capsys, "robot", str(KX1), "--regions", "hand,chest")
    data = json.loads(out)
    assert set(data["base_safe_speed_mps"]) == {"hand", "chest"}
    assert any(p["entry"] == "/cmd_vel" and p["guarded_by"] == [] for p in data["velocity_paths"])
    _code, out, _ = run(capsys, "checks")
    assert "CZL-001" in out and "AML.T0051.001" in out


def test_errors_exit_1(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path))
    assert code == 1 and "fleet.yaml" in err


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "caziel" in capsys.readouterr().out


NODE_INFO = """/collision_monitor
  Subscribers:
    /cmd_vel_smoothed: geometry_msgs/msg/Twist
    /parameter_events: rcl_interfaces/msg/ParameterEvent
  Publishers:
    /cmd_vel: geometry_msgs/msg/Twist
    /rosout: rcl_interfaces/msg/Log
  Service Servers:
    /collision_monitor/change_state: lifecycle_msgs/srv/ChangeState
    /collision_monitor/get_parameters: rcl_interfaces/srv/GetParameters
  Service Clients:

  Action Servers:

  Action Clients:
    /navigate_to_pose: nav2_msgs/action/NavigateToPose
"""


def test_parse_node_info():
    n = snapshot.parse_node_info(NODE_INFO)
    assert n["name"] == "/collision_monitor"
    assert n["subscribers"] == [{"name": "/cmd_vel_smoothed", "type": "geometry_msgs/msg/Twist"}]
    assert n["publishers"] == [{"name": "/cmd_vel", "type": "geometry_msgs/msg/Twist"}]
    assert [s["name"] for s in n["services"]] == ["/collision_monitor/change_state"]
    assert n["action_servers"] == []
    with pytest.raises(ValueError):
        snapshot.parse_node_info("  ")


def test_capture_with_fake_ros2():
    def runner(cmd):
        if cmd[:3] == ["ros2", "node", "list"]:
            return "/collision_monitor\n/broken\n"
        if cmd[-1] == "/broken":
            raise ValueError("boom")
        if cmd[:3] == ["ros2", "param", "dump"]:
            return f"{cmd[-1]}:\n  ros__parameters: {{}}\n"
        return NODE_INFO

    data = snapshot.capture(runner, env={"ROS_SECURITY_ENABLE": "false", "ROS_DISTRO": "jazzy", "HOME": "/x"})
    assert data["ros_distro"] == "jazzy" and "HOME" not in data["environment"]
    assert data["nodes"][0]["name"] == "/broken" and "error" in data["nodes"][0]
    assert "ros__parameters" in snapshot.dump_params(["/a"], runner)


def test_snapshot_without_ros(monkeypatch):
    monkeypatch.setattr(snapshot.shutil, "which", lambda _: None)
    with pytest.raises(SystemExit):
        snapshot.main("x.json")


def test_compare_table(tmp_path):
    from caziel import policy

    _, before, after = policy.fix(FLEET, tmp_path / "h")
    table = report.compare_table(before, after)
    assert "`agent:dispatch-agent` | 12 → 0" in table
