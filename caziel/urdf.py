"""Read just enough of a URDF to bound what an arm or mobile base can physically do.

Caziel does not need full kinematics. For a blast-radius estimate it needs:
  * total mass (a mobile base carries everything on it)
  * the moving mass of the arm chain
  * the chain's reach at full extension
  * an upper bound on tool-tip speed: each joint at its velocity limit, with the
    rest of the chain stretched straight out from that joint. Real tip speed is lower;
    this is the number a hijacked controller could approach, not the one a planner uses.
"""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Joint:
    name: str
    type: str
    parent: str
    child: str
    origin: tuple[float, float, float] = (0.0, 0.0, 0.0)
    lower: float | None = None
    upper: float | None = None
    velocity: float | None = None
    effort: float | None = None

    @property
    def actuated(self) -> bool:
        return self.type in ("revolute", "continuous", "prismatic")

    @property
    def offset(self) -> float:
        return math.sqrt(sum(c * c for c in self.origin))


@dataclass
class Robot:
    name: str
    link_mass: dict[str, float] = field(default_factory=dict)
    joints: dict[str, Joint] = field(default_factory=dict)

    @property
    def total_mass(self) -> float:
        return sum(self.link_mass.values())

    def joint_to_child(self, link: str) -> Joint | None:
        for j in self.joints.values():
            if j.child == link:
                return j
        return None

    def chain(self, root: str, tip: str) -> list[Joint]:
        """Joints from root link down to tip link, in order."""
        path: list[Joint] = []
        link = tip
        while link != root:
            j = self.joint_to_child(link)
            if j is None:
                raise ValueError(f"no kinematic path from {root!r} to {tip!r} in {self.name}")
            path.append(j)
            link = j.parent
        return list(reversed(path))


@dataclass
class ArmEnvelope:
    joints: list[str]
    reach_m: float
    moving_mass_kg: float
    tip_speed_bound_mps: float
    per_joint: list[dict[str, float | str]]


def _floats(text: str | None, default: tuple[float, float, float]) -> tuple[float, float, float]:
    if not text:
        return default
    parts = [float(x) for x in text.split()]
    if len(parts) != 3:
        raise ValueError(f"expected 3 numbers, got {text!r}")
    return (parts[0], parts[1], parts[2])


def _opt(el: ET.Element | None, attr: str) -> float | None:
    if el is None or el.get(attr) is None:
        return None
    return float(el.get(attr, "0"))


def parse(path: str | Path) -> Robot:
    tree = ET.parse(str(path))
    root = tree.getroot()
    if root.tag != "robot":
        raise ValueError(f"{path}: not a URDF (root element is <{root.tag}>)")
    robot = Robot(name=root.get("name", "robot"))
    for link in root.findall("link"):
        mass_el = link.find("inertial/mass")
        robot.link_mass[link.get("name", "")] = float(mass_el.get("value", "0")) if mass_el is not None else 0.0
    for j in root.findall("joint"):
        limit = j.find("limit")
        origin = j.find("origin")
        parent, child = j.find("parent"), j.find("child")
        if parent is None or child is None:
            raise ValueError(f"{path}: joint {j.get('name')!r} is missing <parent> or <child>")
        joint = Joint(
            name=j.get("name", ""),
            type=j.get("type", "fixed"),
            parent=parent.get("link", ""),
            child=child.get("link", ""),
            origin=_floats(origin.get("xyz") if origin is not None else None, (0.0, 0.0, 0.0)),
            lower=_opt(limit, "lower"),
            upper=_opt(limit, "upper"),
            velocity=_opt(limit, "velocity"),
            effort=_opt(limit, "effort"),
        )
        robot.joints[joint.name] = joint
    return robot


def arm_envelope(robot: Robot, root: str, tip: str) -> ArmEnvelope:
    chain = robot.chain(root, tip)
    actuated = [j for j in chain if j.actuated]
    if not actuated:
        raise ValueError(f"arm chain {root}->{tip} has no actuated joints")
    first = chain.index(actuated[0])
    # Segment lengths after the first actuated joint define the reach.
    segments = [j.offset for j in chain[first + 1 :]]
    reach = sum(segments)
    moving_links = {j.child for j in chain[first:]}
    moving_mass = sum(robot.link_mass.get(link, 0.0) for link in moving_links)

    per_joint: list[dict[str, float | str]] = []
    bound = 0.0
    for j in actuated:
        idx = chain.index(j)
        lever = sum(seg.offset for seg in chain[idx + 1 :])
        vel = j.velocity or 0.0
        contribution = vel if j.type == "prismatic" else vel * lever
        bound += contribution
        per_joint.append(
            {
                "joint": j.name,
                "type": j.type,
                "limit": vel,
                "lever_m": round(lever, 3),
                "tip_mps": round(contribution, 3),
            }
        )
    return ArmEnvelope(
        joints=[j.name for j in actuated],
        reach_m=reach,
        moving_mass_kg=moving_mass,
        tip_speed_bound_mps=bound,
        per_joint=per_joint,
    )
