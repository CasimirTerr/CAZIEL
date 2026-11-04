import io
import json

import pytest

from caziel import cli, cloud, live

from .conftest import FLEET

TRAFFIC = FLEET / "traffic" / "shift.jsonl"


@pytest.fixture()
def watcher(fleet):
    return live.Watcher(fleet)


def ev(topic, principal, **payload):
    return {"ts": 1, "topic": topic, "principal": principal, "payload": payload}


def test_attribution(watcher):
    a = watcher.attribute("AROA4HRBRFLEETTOOLS:fleet-nudge")
    assert a.actor == "agent:dispatch-agent" and a.via == "dispatch-agent.nudge (as fleet-tools-role)"
    a = watcher.attribute("AROA4HRBROPSCONSOLE:operator-kpatel")
    assert a.actor == "principal:ops-console-role" and "operator-kpatel" in a.via
    assert watcher.attribute("AIDA4HRBRVENDORSUP1").actor == "principal:vendor-support"
    arn = "arn:aws:sts::111122223333:assumed-role/fleet-tools-role/fleet-pick"
    assert watcher.attribute(arn).actor == "agent:dispatch-agent"
    assert watcher.attribute("AROANOBODY:x").actor == "unknown"


def test_nudge_skips_collision_monitor(watcher):
    v = watcher.classify(ev("fleet/kx1-03/cmd/velocity", "AROA4HRBRFLEETTOOLS:fleet-nudge", linear={"x": 1.9}))
    assert v.severity == "critical" and "CZL-001" in v.tags
    assert v.contact_speed_mps == pytest.approx(1.9)
    assert v.exposure["region"] == "thigh"


def test_slow_operator_nudge_is_medium_not_critical(watcher):
    v = watcher.classify(ev("fleet/kx1-03/cmd/velocity", "AROA4HRBROPSCONSOLE:op", linear={"x": 0.1}))
    assert v.severity == "medium" and v.exposure["ratio"] < 1


def test_navigation_is_guarded(watcher):
    v = watcher.classify(ev("fleet/kx1-03/cmd/navigate", "AROA4HRBRSUPERVISOR:tablet"))
    assert v.severity == "info" and v.title == "Guarded motion" and v.contact_speed_mps == 0


def test_parameter_write_then_pick_is_tracked_per_robot(watcher):
    pick = ev("fleet/kx1-07/cmd/pick", "AROA4HRBRFLEETTOOLS:fleet-pick")
    assert watcher.classify(pick).severity == "info"
    p = watcher.classify(
        ev(
            "fleet/kx1-07/cmd/param",
            "AROA4HRBRFLEETTOOLS:fleet-tune",
            node="/move_group",
            name="default_velocity_scaling_factor",
            value=1.0,
        )
    )
    assert p.severity == "high" and "CZL-003" in p.tags
    after = watcher.classify(pick)
    assert after.severity == "critical" and "limits-lifted" in after.tags
    # other robots are untouched
    assert watcher.classify(ev("fleet/kx1-08/cmd/pick", "AROA4HRBRFLEETTOOLS:fleet-pick")).severity == "info"


def test_harmless_param_and_lifecycle(watcher):
    v = watcher.classify(ev("fleet/kx1-01/cmd/param", "AIDA4HRBRVENDORSUP1", node="/lidar_driver", name="rate"))
    assert v.severity == "info" and v.title == "Parameter write"
    v = watcher.classify(
        ev("fleet/kx1-01/cmd/lifecycle", "AIDA4HRBRVENDORSUP1", node="/planner_server", transition="activate")
    )
    assert v.severity == "info" and v.title == "Lifecycle command"
    v = watcher.classify(
        ev("fleet/kx1-01/cmd/lifecycle", "AIDA4HRBRVENDORSUP1", node="/collision_monitor", transition="deactivate")
    )
    assert v.severity == "high"


def test_raw_arm_and_other_commands(watcher):
    v = watcher.classify(ev("fleet/kx1-10/cmd/arm", "AIDA4HRBRVENDORSUP1"))
    assert v.severity == "critical" and "CZL-004" in v.tags and v.actuator == "arm"
    v = watcher.classify(ev("fleet/kx1-10/cmd/dock", "AROA4HRBROPSCONSOLE:op"))
    assert v.title == "Other command"


def test_unmapped_unknown_and_foreign_topics(watcher):
    assert watcher.classify(ev("fleet/kx1-10/cmd/selfdestruct", "AIDA4HRBRVENDORSUP1")).title.startswith("Dropped")
    assert watcher.classify(ev("weather/today", "AIDA4HRBRVENDORSUP1")).title == "Not a fleet topic"
    v = watcher.classify(ev("fleet/kx1-10/cmd/navigate", "AROAZZZ:temp"))
    assert v.severity == "medium" and v.actor == "unknown"


def test_iam_denial(tmp_path):
    from caziel import policy

    policy.fix(FLEET, tmp_path / "h")
    w = live.Watcher(cloud.load(tmp_path / "h"))
    v = w.classify(ev("fleet/kx1-10/cmd/arm", "AIDA4HRBRVENDORSUP1"))
    assert v.title == "Denied by IAM" and v.severity == "info" and "policy-denies" in v.tags
    v = w.classify(ev("fleet/kx1-07/cmd/velocity", "AROA4HRBRFLEETTOOLS:fleet-nudge", linear={"x": 1.9}))
    assert v.title == "Held for human approval" and v.contact_speed_mps == 0
    v = w.classify(ev("fleet/kx1-10/cmd/lifecycle", "AIDA4HRBRVENDORSUP1", node="/collision_monitor"))
    assert v.title.startswith("Dropped")


def test_sample_shift_has_the_three_incidents(watcher):
    with TRAFFIC.open() as f:
        verdicts = list(watcher.watch(live.read_events(f)))
    crit = [v for v in verdicts if v.severity == "critical"]
    assert {v.thing for v in crit} == {"kx1-07", "kx1-10"}
    assert sum(1 for v in verdicts if v.actor == "unknown") == 3
    assert json.dumps([v.to_dict() for v in verdicts])


def test_read_events_errors():
    assert list(live.read_events(io.StringIO('# comment\n\n{"a": 1}\n'))) == [{"a": 1}]
    with pytest.raises(ValueError, match="line 1"):
        list(live.read_events(io.StringIO("nope\n")))


def test_watch_cli(capsys, monkeypatch):
    code = cli.main(["watch", str(FLEET), str(TRAFFIC), "--json", "--min-severity", "high", "--fail-on", "critical"])
    out = capsys.readouterr()
    assert code == 2
    lines = [json.loads(x) for x in out.out.splitlines()]
    assert len(lines) == 8 and all(x["severity"] in ("high", "critical") for x in lines)
    assert "161 events" in out.err
    monkeypatch.setattr("sys.stdin", io.StringIO(TRAFFIC.read_text()))
    code = cli.main(["watch", str(FLEET), "--no-color"])
    assert code == 0 and "CRITICAL" in capsys.readouterr().out
