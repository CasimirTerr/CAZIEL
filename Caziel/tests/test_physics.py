import math

import pytest

from caziel import physics


def test_energy_limit_formula():
    chest = physics.BODY_REGIONS["chest"]
    assert chest.energy_limit_j == pytest.approx(280**2 / (2 * 25_000))


@pytest.mark.parametrize("region", list(physics.BODY_REGIONS))
def test_safe_speed_lands_exactly_on_the_limit(region):
    r = physics.BODY_REGIONS[region]
    v = physics.safe_speed(r, 116.28)
    assert physics.impact_energy(r, 116.28, v) == pytest.approx(r.energy_limit_j)


def test_heavier_robot_means_lower_safe_speed():
    r = physics.BODY_REGIONS["thigh"]
    assert physics.safe_speed(r, 200) < physics.safe_speed(r, 50)


def test_reduced_mass_and_arm_mass():
    assert physics.reduced_mass(40, 40) == pytest.approx(20)
    assert physics.arm_effective_mass(10.7, 4) == pytest.approx(9.35)
    with pytest.raises(ValueError):
        physics.reduced_mass(0, 1)


def test_zero_speed_is_zero_energy():
    assert physics.impact_energy(physics.BODY_REGIONS["hand"], 100, 0) == 0


def test_exposure_ratio():
    (e,) = physics.exposures(["chest"], 116.28, 2.0)
    assert e.ratio == pytest.approx(e.energy_j / e.limit_j)
    assert e.to_dict()["region"] == "chest"
    assert math.isclose(e.safe_speed_mps, 0.324, abs_tol=0.01)


def test_region_overrides_do_not_mutate_defaults():
    table = physics.region_table({"chest": {"force_n": 200}})
    assert table["chest"].force_n == 200
    assert physics.BODY_REGIONS["chest"].force_n == 280
    with pytest.raises(ValueError):
        physics.region_table({"tail": {}})
