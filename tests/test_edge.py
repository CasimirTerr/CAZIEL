import pytest

from caziel import edge

from .conftest import KX1


def access(**kw):
    a = edge.Access()
    for k, v in kw.items():
        getattr(a, k).update(v) if isinstance(getattr(a, k), (dict, set)) else setattr(a, k, v)
    return a


def test_direct_velocity_bypasses_collision_monitor(model):
    r = edge.reach(model, access(topics={"/cmd_vel": "test"}))
    (route,) = r.routes
    assert route.kind == "direct"
    assert route.bypassed_guards == ["/collision_monitor"]
    assert route.contact_speed == pytest.approx(2.0)


def test_navigation_is_capped_and_guarded(model):
    r = edge.reach(model, access(actions={"/navigate_to_pose": "test"}))
    (route,) = r.routes
    assert route.kind == "nav"
    assert route.speed_mps == pytest.approx(0.5)
    assert route.active_guards == ["/collision_monitor"]
    assert route.contact_speed == 0


def test_parameter_writes_unlock_navigation(model):
    r = edge.reach(model, access(actions={"/navigate_to_pose": "t"}, param_nodes={"*": "t"}))
    (route,) = r.routes
    assert route.speed_mps == pytest.approx(2.0)
    assert route.active_guards == []
    assert set(route.unlocked) == {"/controller_server", "/velocity_smoother"}
    assert "/collision_monitor" in r.disabled_guards
    assert route.contact_speed == pytest.approx(2.0)


def test_moveit_scaling_and_raw_arm(model):
    r = edge.reach(model, access(actions={"/move_action": "t", "/arm_controller/follow_joint_trajectory": "t"}))
    planned = next(x for x in r.routes if x.kind == "planned")
    raw = next(x for x in r.routes if x.kind == "raw")
    assert planned.speed_mps == pytest.approx(0.479)
    assert raw.speed_mps == pytest.approx(4.79)
    assert r.contact_speed("arm") == pytest.approx(4.79)


def test_raw_trajectory_topic(model):
    r = edge.reach(model, access(topics={"/arm_controller/joint_trajectory": "t"}))
    assert r.worst("arm").kind == "raw"


def test_gated_routes_do_not_reach_people(model):
    r = edge.reach(model, access(topics={"/cmd_vel": "t"}, gated={"/cmd_vel"}))
    assert r.routes[0].gated
    assert r.contact_speed("base") == 0


def test_code_execution_ignores_every_layer(model):
    r = edge.reach(model, access(code_exec="deploy"))
    assert r.contact_speed("base") == pytest.approx(2.0)
    assert r.contact_speed("arm") == pytest.approx(4.79)
    assert r.disabled_guards == {"/collision_monitor": "deploy"}


def test_unknown_actions_and_empty_reach(model):
    r = edge.reach(model, access(actions={"/dock_robot": "t", "/not_there": "t"}))
    assert r.routes == []
    assert r.worst("base") is None and r.contact_speed("arm") == 0


def test_lifecycle_makes_safety_stoppable(model):
    r = edge.reach(model, access(lifecycle_nodes={"/collision_monitor": "t"}))
    assert r.stoppable == {"/collision_monitor": "t"}


def test_access_merge_and_signature():
    a, b = edge.Access(), edge.Access()
    m = edge.Mapping("x/{thing}", "parameters", nodes=[])
    b.add(m, "how")
    b.add(edge.Mapping("y/{thing}", "lifecycle", nodes=["/a"]), "how")
    b.add(edge.Mapping("z/{thing}", "action", name="/act", requires_approval=True), "how")
    a.merge(b)
    assert a.param_nodes == {"*": "how"} and a.lifecycle_nodes == {"/a": "how"}
    assert "/act" in a.gated and not a.empty()


def test_bridge_load_rejects_unknown_kind(tmp_path):
    p = tmp_path / "b.yaml"
    p.write_text("mappings:\n  - mqtt: a\n    ros: {kind: teleport}\n")
    with pytest.raises(ValueError):
        edge.Bridge.load(p)


def test_bridge_loads(model):
    b = edge.Bridge.load(KX1 / "bridge.yaml")
    assert b.lan_endpoint == "0.0.0.0:9090" and not b.ros_security
    assert b.mappings[0].topic_for("kx1-01") == "fleet/kx1-01/cmd/navigate"


def test_route_dict(model):
    r = edge.reach(model, access(topics={"/cmd_vel": "t"}))
    d = r.routes[0].to_dict()
    assert d["contact_speed_mps"] == 2.0 and d["path"][0] == "/cmd_vel"
