"""Transient-contact energy model in the style of ISO/TS 15066 (power and force limiting).

ISO/TS 15066 treats a collision as a fully inelastic two-body impact and the body region
as a linear spring. The energy the body can absorb before the pain threshold is

    E_max = F_max^2 / (2 k)

and the energy actually transferred at relative speed v is

    E = 1/2 * mu * v^2,   mu = (1/m_H + 1/m_R)^-1

where m_H is the effective mass of the body region and m_R the effective mass of the
robot. For an arm the standard uses m_R = M/2 + m_payload. A mobile base moves as one
rigid body, so Caziel uses its full mass plus payload.

The body-region values below are the ones commonly cited from ISO/TS 15066:2016 Annex A
(transient limits = 2x quasi-static force). That annex now lives on as informative
Annex M of ISO 10218-2:2025. Check them against your own copy of the standard and override
them in fleet.yaml if your safety team uses different numbers.

This is an estimate for prioritising security work, not a certified safety assessment.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class BodyRegion:
    key: str
    label: str
    force_n: float  # transient force limit
    k_n_per_m: float  # effective spring constant
    mass_kg: float  # effective body mass

    @property
    def energy_limit_j(self) -> float:
        return self.force_n**2 / (2.0 * self.k_n_per_m)


BODY_REGIONS: dict[str, BodyRegion] = {
    r.key: r
    for r in (
        BodyRegion("hand", "Hand and fingers", 280.0, 75_000.0, 0.6),
        BodyRegion("forearm", "Lower arm and wrist", 320.0, 40_000.0, 2.0),
        BodyRegion("upper_arm", "Upper arm and elbow", 300.0, 30_000.0, 3.0),
        BodyRegion("chest", "Chest", 280.0, 25_000.0, 40.0),
        BodyRegion("abdomen", "Abdomen", 220.0, 10_000.0, 40.0),
        BodyRegion("thigh", "Thigh and knee", 440.0, 50_000.0, 75.0),
    )
}

# Head and neck: ISO/TS 15066 does not allow transient contact at all.
NO_CONTACT_REGIONS = ("head", "face", "neck")


def reduced_mass(m_body: float, m_robot: float) -> float:
    if m_body <= 0 or m_robot <= 0:
        raise ValueError("masses must be positive")
    return 1.0 / (1.0 / m_body + 1.0 / m_robot)


def arm_effective_mass(moving_mass: float, payload: float) -> float:
    return moving_mass / 2.0 + payload


def impact_energy(region: BodyRegion, robot_mass: float, speed: float) -> float:
    if speed <= 0:
        return 0.0
    return 0.5 * reduced_mass(region.mass_kg, robot_mass) * speed * speed


def safe_speed(region: BodyRegion, robot_mass: float) -> float:
    """Highest relative speed that stays inside the region's transient limit."""
    mu = reduced_mass(region.mass_kg, robot_mass)
    return region.force_n / math.sqrt(mu * region.k_n_per_m)


@dataclass
class Exposure:
    region: str
    label: str
    energy_j: float
    limit_j: float
    safe_speed_mps: float

    @property
    def ratio(self) -> float:
        return self.energy_j / self.limit_j if self.limit_j else 0.0

    def to_dict(self) -> dict[str, float | str]:
        return {
            "region": self.region,
            "label": self.label,
            "energy_j": round(self.energy_j, 3),
            "limit_j": round(self.limit_j, 3),
            "ratio": round(self.ratio, 2),
            "safe_speed_mps": round(self.safe_speed_mps, 3),
        }


def exposures(
    regions: list[str], robot_mass: float, speed: float, table: dict[str, BodyRegion] | None = None
) -> list[Exposure]:
    table = table or BODY_REGIONS
    out = []
    for key in regions:
        r = table[key]
        out.append(
            Exposure(key, r.label, impact_energy(r, robot_mass, speed), r.energy_limit_j, safe_speed(r, robot_mass))
        )
    return out


def region_table(overrides: dict[str, dict[str, float]] | None = None) -> dict[str, BodyRegion]:
    """The body-region table with any per-fleet overrides applied. Never mutates the defaults."""
    table = dict(BODY_REGIONS)
    for key, vals in (overrides or {}).items():
        base = table.get(key)
        if base is None:
            raise ValueError(f"unknown body region {key!r}; known: {', '.join(sorted(table))}")
        table[key] = BodyRegion(
            key,
            base.label,
            float(vals.get("force_n", base.force_n)),
            float(vals.get("k_n_per_m", base.k_n_per_m)),
            float(vals.get("mass_kg", base.mass_kg)),
        )
    return table
