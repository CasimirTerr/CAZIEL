import pytest

from caziel import ros

from .conftest import KX1


def test_params_are_flattened(model):
    assert model.params["/collision_monitor"]["PolygonStop.action_type"] == "stop"
    assert model.params["/diff_drive_controller"]["linear.x.max_velocity"] == 2.0


def test_roles(model):
    assert model.roles["/collision_monitor"] == "collision_monitor"
    assert model.roles["/velocity_smoother"] == "velocity_smoother"
    assert model.roles["/controller_server"] == "controller_server"
    assert model.roles["/move_group"] == "move_group"
    assert model.roles["/lidar_driver"] == "other"
    assert ros.node_role("/safety_controller", {}) == "collision_monitor"


def test_cmd_vel_goes_straight_to_the_wheels(model):
    (path,) = model.twist_paths("/cmd_vel")
    assert path.nodes == []


def test_navigation_passes_the_collision_monitor(model):
    assert model.nav_entry_topics() == ["/cmd_vel_nav"]
    (path,) = model.twist_paths("cmd_vel_nav")
    assert path.nodes == ["/velocity_smoother", "/collision_monitor"]
    assert path.through(model.roles, ros.SAFETY_ROLES) == ["/collision_monitor"]


def test_limits(model):
    assert model.base_hardware_speed() == 2.0
    assert model.limiter_speed("/velocity_smoother") == 0.5
    assert model.limiter_speed("/controller_server") == 0.5
    assert model.limiter_speed("/lidar_driver") is None
    assert model.moveit_scaling() == 0.1
    assert model.base_mass == pytest.approx(116.28)


def test_hardware_speed_fallback(tmp_path):
    import shutil

    d = tmp_path / "r"
    shutil.copytree(KX1, d)
    p = d / "params.yaml"
    p.write_text(
        p.read_text().replace(
            "has_velocity_limits: true\n        max_velocity: 2.0",
            "has_velocity_limits: false\n        max_velocity: 2.0",
        )
    )
    m = ros.RobotModel.load(d)
    assert m.base_hardware_speed() == 2.2


def test_graph_security_flag(model):
    assert model.graph.security_enabled is False
    assert model.graph.domain_id == 7
    assert model.graph.action_server("/move_action").name == "/move_group"
    assert model.graph.action_server("/nope") is None


def test_summary(model):
    s = model.summary()
    assert s["safety_nodes"] == ["/collision_monitor"]
    assert s["arm"]["reach_m"] == 1.0


def test_params_skip_wildcard_nodes(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("/**:\n  ros__parameters:\n    use_sim_time: true\nfoo:\n  ros__parameters:\n    a: {b: 1}\n")
    assert ros.load_params(p) == {"/foo": {"a.b": 1}}
