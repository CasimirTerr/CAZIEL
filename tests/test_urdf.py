import pytest

from caziel import urdf

from .conftest import KX1


def test_masses_and_joints():
    r = urdf.parse(KX1 / "robot.urdf")
    assert r.name == "kx1"
    assert r.total_mass == pytest.approx(112.28)
    assert r.joints["elbow_joint"].velocity == 2.0
    assert r.joints["left_wheel_joint"].actuated


def test_arm_envelope_bound():
    r = urdf.parse(KX1 / "robot.urdf")
    env = urdf.arm_envelope(r, "arm_mount", "gripper_tcp")
    assert env.joints == ["shoulder_pan_joint", "shoulder_lift_joint", "elbow_joint", "wrist_joint"]
    assert env.reach_m == pytest.approx(1.0)
    assert env.moving_mass_kg == pytest.approx(10.7)
    # 1.6*1.0 + 1.6*0.9 + 2.0*0.55 + 2.6*0.25
    assert env.tip_speed_bound_mps == pytest.approx(4.79)


def test_bad_chain(tmp_path):
    r = urdf.parse(KX1 / "robot.urdf")
    with pytest.raises(ValueError):
        r.chain("arm_mount", "left_wheel")
    with pytest.raises(ValueError):
        urdf.arm_envelope(r, "gripper_link", "gripper_tcp")


def test_rejects_non_urdf(tmp_path):
    p = tmp_path / "x.urdf"
    p.write_text("<sdf/>")
    with pytest.raises(ValueError):
        urdf.parse(p)
    p.write_text('<robot name="r"><joint name="j" type="fixed"><parent link="a"/></joint></robot>')
    with pytest.raises(ValueError):
        urdf.parse(p)
    p.write_text(
        '<robot name="r"><link name="a"/><joint name="j" type="fixed"><parent link="a"/>'
        '<child link="b"/><origin xyz="1 2"/></joint></robot>'
    )
    with pytest.raises(ValueError):
        urdf.parse(p)
