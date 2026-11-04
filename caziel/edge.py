"""The robot's edge bridge, and what a set of reachable commands means physically.

The bridge is the piece that turns cloud messages (AWS IoT Core MQTT) into ROS 2 calls on
the robot, usually a Greengrass component. Its mapping table decides which cloud topics
can touch which ROS interfaces, so it is the hinge between the cloud half of the analysis
and the physical half.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import physics, ros

KINDS = ("topic", "action", "parameters", "lifecycle", "service")


@dataclass
class Mapping:
    mqtt: str
    kind: str
    name: str = ""
    type: str = ""
    nodes: list[str] = field(default_factory=list)
    requires_approval: bool = False
    note: str = ""

    def topic_for(self, thing: str) -> str:
        return self.mqtt.replace("{thing}", thing)


@dataclass
class Bridge:
    name: str
    runtime: str
    mappings: list[Mapping]
    ros_security: bool
    lan_endpoint: str | None
    lan_auth: str

    @classmethod
    def load(cls, path: str | Path) -> Bridge:
        raw = yaml.safe_load(Path(path).read_text()) or {}
        maps = []
        for m in raw.get("mappings", []):
            target = m.get("ros", {})
            kind = target.get("kind", "")
            if kind not in KINDS:
                raise ValueError(f"{path}: mapping {m.get('mqtt')!r} has unknown kind {kind!r}")
            maps.append(
                Mapping(
                    mqtt=m["mqtt"],
                    kind=kind,
                    name=target.get("name", ""),
                    type=target.get("type", ""),
                    nodes=[str(n) for n in target.get("nodes", [])],
                    requires_approval=bool(m.get("requires_approval", False)),
                    note=m.get("note", ""),
                )
            )
        lan = raw.get("lan") or {}
        return cls(
            name=raw.get("name", "edge-bridge"),
            runtime=raw.get("runtime", "unknown"),
            mappings=maps,
            ros_security=bool((raw.get("ros_security") or {}).get("enabled", False)),
            lan_endpoint=lan.get("endpoint"),
            lan_auth=str(lan.get("auth", "none")),
        )


# --------------------------------------------------------------------------- access → reach


@dataclass
class Access:
    """Everything one actor can make one robot's ROS graph do."""

    topics: dict[str, str] = field(default_factory=dict)  # ros topic -> how (mqtt topic)
    actions: dict[str, str] = field(default_factory=dict)
    param_nodes: dict[str, str] = field(default_factory=dict)  # node or "*" -> how
    lifecycle_nodes: dict[str, str] = field(default_factory=dict)
    gated: set[str] = field(default_factory=set)  # ros interfaces behind human approval
    code_exec: str = ""  # how, if the actor can run code on the robot

    def add(self, m: Mapping, how: str) -> None:
        if m.kind == "topic":
            self.topics.setdefault(ros._norm(m.name), how)
        elif m.kind == "action":
            self.actions.setdefault(ros._norm(m.name), how)
        elif m.kind == "parameters":
            for n in m.nodes or ["*"]:
                self.param_nodes.setdefault(n if n == "*" else ros._norm(n), how)
        elif m.kind == "lifecycle":
            for n in m.nodes or ["*"]:
                self.lifecycle_nodes.setdefault(n if n == "*" else ros._norm(n), how)
        if m.requires_approval and m.name:
            self.gated.add(ros._norm(m.name))

    def merge(self, other: Access) -> None:
        for attr in ("topics", "actions", "param_nodes", "lifecycle_nodes"):
            mine = getattr(self, attr)
            for k, v in getattr(other, attr).items():
                mine.setdefault(k, v)
        self.gated |= other.gated
        self.code_exec = self.code_exec or other.code_exec

    def empty(self) -> bool:
        return not (self.topics or self.actions or self.param_nodes or self.lifecycle_nodes or self.code_exec)

    def can_write_params(self, node: str) -> str:
        return self.param_nodes.get(node) or self.param_nodes.get("*") or self.code_exec

    def can_lifecycle(self, node: str) -> str:
        return self.lifecycle_nodes.get(node) or self.lifecycle_nodes.get("*") or self.code_exec


@dataclass
class Route:
    actuator: str  # "base" or "arm"
    kind: str  # direct | nav | raw | planned | code
    entry: str
    how: str
    path: list[str]
    speed_mps: float
    active_guards: list[str]
    bypassed_guards: list[str]
    unlocked: list[str]
    gated: bool

    @property
    def contact_speed(self) -> float:
        """Speed at which the robot can actually meet a person on this route."""
        if self.gated:
            return 0.0
        if self.actuator == "base" and self.active_guards:
            return 0.0
        return self.speed_mps

    def to_dict(self) -> dict[str, Any]:
        return {
            "actuator": self.actuator,
            "kind": self.kind,
            "entry": self.entry,
            "how": self.how,
            "path": self.path,
            "speed_mps": round(self.speed_mps, 3),
            "contact_speed_mps": round(self.contact_speed, 3),
            "active_guards": self.active_guards,
            "bypassed_guards": self.bypassed_guards,
            "unlocked": self.unlocked,
            "gated": self.gated,
        }


@dataclass
class Reach:
    routes: list[Route]
    disabled_guards: dict[str, str]  # node -> how (parameter write)
    stoppable: dict[str, str]  # safety node -> how (lifecycle)
    code_exec: str

    def worst(self, actuator: str) -> Route | None:
        cands = [r for r in self.routes if r.actuator == actuator]
        if not cands:
            return None
        return max(cands, key=lambda r: (r.contact_speed, r.speed_mps))

    def contact_speed(self, actuator: str) -> float:
        w = self.worst(actuator)
        return w.contact_speed if w else 0.0


def _base_route(
    model: ros.RobotModel,
    access: Access,
    kind: str,
    entry: str,
    how: str,
    path: ros.TwistPath,
    extra_limiters: list[str],
) -> Route:
    unlocked: list[str] = []
    speed = model.base_hardware_speed()
    for node in [*extra_limiters, *path.nodes]:
        if model.roles.get(node) not in ros.LIMITER_ROLES:
            continue
        if access.can_write_params(node):
            unlocked.append(node)
            continue
        lim = model.limiter_speed(node)
        if lim is not None:
            speed = min(speed, lim)
    on_path = path.through(model.roles, ros.SAFETY_ROLES)
    active = [g for g in on_path if not access.can_write_params(g)]
    bypassed = [g for g in model.safety_nodes() if g not in path.nodes]
    return Route(
        "base",
        kind,
        entry,
        how,
        [entry, *extra_limiters, *path.nodes, model.base_controller],
        speed,
        active,
        bypassed,
        unlocked,
        entry in access.gated,
    )


def reach(model: ros.RobotModel, access: Access) -> Reach:
    routes: list[Route] = []

    for topic, how in sorted(access.topics.items()):
        for p in model.twist_paths(topic):
            routes.append(_base_route(model, access, "direct", topic, how, p, []))
        if model.arm and model.graph.topic_type(topic) == ros.TRAJECTORY_TOPIC:
            routes.append(
                Route(
                    "arm", "raw", topic, how, [topic], model.arm.tip_speed_bound_mps, [], [], [], topic in access.gated
                )
            )

    for action, how in sorted(access.actions.items()):
        server = model.graph.action_server(action)
        if server is None:
            continue
        atype = next(e.type for e in server.action_servers if e.name == action)
        if atype in ros.NAV_ACTIONS:
            controllers = [n for n, r in model.roles.items() if r == "controller_server"]
            for t in model.nav_entry_topics():
                for p in model.twist_paths(t):
                    routes.append(_base_route(model, access, "nav", action, how, p, controllers))
        elif model.arm and atype == ros.TRAJECTORY_ACTION:
            routes.append(
                Route(
                    "arm",
                    "raw",
                    action,
                    how,
                    [action, server.name],
                    model.arm.tip_speed_bound_mps,
                    [],
                    ["MoveIt planning"] if model.moveit_node() else [],
                    [],
                    action in access.gated,
                )
            )
        elif model.arm and atype == ros.MOVEIT_ACTION:
            mg = model.moveit_node()
            unlocked = [mg] if mg and access.can_write_params(mg) else []
            scale = 1.0 if unlocked else model.moveit_scaling()
            routes.append(
                Route(
                    "arm",
                    "planned",
                    action,
                    how,
                    [action, server.name],
                    model.arm.tip_speed_bound_mps * scale,
                    ["MoveIt planning"],
                    [],
                    unlocked,
                    action in access.gated,
                )
            )

    if access.code_exec:
        routes.append(
            Route(
                "base",
                "code",
                "robot software",
                access.code_exec,
                [model.base_controller],
                model.base_hardware_speed(),
                [],
                model.safety_nodes(),
                [],
                False,
            )
        )
        if model.arm:
            routes.append(
                Route(
                    "arm",
                    "code",
                    "robot software",
                    access.code_exec,
                    ["arm controller"],
                    model.arm.tip_speed_bound_mps,
                    [],
                    [],
                    [],
                    False,
                )
            )

    disabled = {g: access.can_write_params(g) for g in model.safety_nodes() if access.can_write_params(g)}
    stoppable = {g: access.can_lifecycle(g) for g in model.safety_nodes() if access.can_lifecycle(g)}
    return Reach(routes, disabled, stoppable, access.code_exec)


def exposures_for(
    model: ros.RobotModel, r: Reach, regions: list[str], table: dict[str, physics.BodyRegion]
) -> dict[str, list[physics.Exposure]]:
    out: dict[str, list[physics.Exposure]] = {}
    base_speed = r.contact_speed("base")
    out["base"] = physics.exposures(regions, model.base_mass, base_speed, table)
    if model.arm:
        arm_mass = physics.arm_effective_mass(model.arm.moving_mass_kg, model.payload)
        out["arm"] = physics.exposures(regions, arm_mass, r.contact_speed("arm"), table)
    return out
