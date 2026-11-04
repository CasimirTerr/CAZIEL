"""The ROS 2 side: parameters, the node graph, and how commands flow to actuators.

The interesting question is not "can the agent publish to /cmd_vel" but "what sits between
that topic and the wheels". Nav2's collision monitor, for example, only protects the robot
if velocity commands pass through it. Caziel walks the velocity dataflow from every entry
point to the base controller and records which safety and limiter nodes are on the way.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import urdf

TWIST_TYPES = {"geometry_msgs/msg/Twist", "geometry_msgs/msg/TwistStamped"}
NAV_ACTIONS = {"nav2_msgs/action/NavigateToPose", "nav2_msgs/action/NavigateThroughPoses"}
TRAJECTORY_ACTION = "control_msgs/action/FollowJointTrajectory"
TRAJECTORY_TOPIC = "trajectory_msgs/msg/JointTrajectory"
MOVEIT_ACTION = "moveit_msgs/action/MoveGroup"


def _norm(name: str) -> str:
    return name if name.startswith("/") else "/" + name


# --------------------------------------------------------------------------- parameters


def load_params(path: str | Path) -> dict[str, dict[str, Any]]:
    """Read a ROS 2 parameter file into {"/node": {"dotted.key": value}}."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    out: dict[str, dict[str, Any]] = {}
    for node, body in raw.items():
        if node.startswith("/**"):
            continue
        params = (body or {}).get("ros__parameters", {}) if isinstance(body, dict) else {}
        flat: dict[str, Any] = {}

        def walk(prefix: str, value: Any, flat: dict[str, Any] = flat) -> None:
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(f"{prefix}.{k}" if prefix else str(k), v)
            else:
                flat[prefix] = value

        walk("", params)
        out[_norm(node)] = flat
    return out


def _first(value: Any) -> float | None:
    if isinstance(value, list):
        return float(value[0]) if value else None
    if value is None:
        return None
    return float(value)


# --------------------------------------------------------------------------- graph


@dataclass
class Endpoint:
    name: str
    type: str


@dataclass
class Node:
    name: str
    publishers: list[Endpoint] = field(default_factory=list)
    subscribers: list[Endpoint] = field(default_factory=list)
    services: list[Endpoint] = field(default_factory=list)
    action_servers: list[Endpoint] = field(default_factory=list)


@dataclass
class Graph:
    nodes: dict[str, Node]
    security_enabled: bool = False
    security_strategy: str = "Permissive"
    domain_id: int = 0

    @classmethod
    def load(cls, path: str | Path) -> Graph:
        data = json.loads(Path(path).read_text())
        nodes: dict[str, Node] = {}
        for raw in data.get("nodes", []):
            n = Node(name=_norm(raw["name"]))
            for attr in ("publishers", "subscribers", "services", "action_servers"):
                setattr(n, attr, [Endpoint(_norm(e["name"]), e["type"]) for e in raw.get(attr, [])])
            nodes[n.name] = n
        env = data.get("environment", {})
        return cls(
            nodes=nodes,
            security_enabled=str(env.get("ROS_SECURITY_ENABLE", "false")).lower() == "true",
            security_strategy=str(env.get("ROS_SECURITY_STRATEGY", "Permissive")),
            domain_id=int(env.get("ROS_DOMAIN_ID", 0)),
        )

    def subscribers_of(self, topic: str) -> list[Node]:
        topic = _norm(topic)
        return [n for n in self.nodes.values() if any(e.name == topic for e in n.subscribers)]

    def topic_type(self, topic: str) -> str | None:
        topic = _norm(topic)
        for n in self.nodes.values():
            for e in n.publishers + n.subscribers:
                if e.name == topic:
                    return e.type
        return None

    def action_server(self, action: str) -> Node | None:
        action = _norm(action)
        for n in self.nodes.values():
            if any(e.name == action for e in n.action_servers):
                return n
        return None

    def topics(self) -> set[str]:
        return {e.name for n in self.nodes.values() for e in n.publishers + n.subscribers}


# --------------------------------------------------------------------------- roles


def node_role(name: str, params: dict[str, Any]) -> str:
    """Recognise the nodes that matter for physical safety from their parameters."""
    keys = set(params)
    if "cmd_vel_in_topic" in keys and ("observation_sources" in keys or "polygons" in keys):
        return "collision_monitor"
    if "max_velocity" in keys and ("smoothing_frequency" in keys or "feedback" in keys):
        return "velocity_smoother"
    if "controller_plugins" in keys or any(k.endswith(".max_vel_x") for k in keys):
        return "controller_server"
    if "default_velocity_scaling_factor" in keys:
        return "move_group"
    short = name.rsplit("/", 1)[-1]
    if short in ("collision_monitor", "safety_controller", "twist_mux_lock"):
        return "collision_monitor"
    return "other"


SAFETY_ROLES = {"collision_monitor"}
LIMITER_ROLES = {"velocity_smoother", "controller_server"}


# --------------------------------------------------------------------------- robot model


@dataclass
class TwistPath:
    entry: str
    nodes: list[str]  # nodes between entry topic and base controller, in order

    def through(self, roles: dict[str, str], wanted: set[str]) -> list[str]:
        return [n for n in self.nodes if roles.get(n) in wanted]


@dataclass
class RobotModel:
    key: str
    directory: Path
    meta: dict[str, Any]
    robot: urdf.Robot
    params: dict[str, dict[str, Any]]
    graph: Graph
    roles: dict[str, str]
    arm: urdf.ArmEnvelope | None

    @classmethod
    def load(cls, directory: str | Path, key: str | None = None) -> RobotModel:
        d = Path(directory)
        meta = yaml.safe_load((d / "robot.yaml").read_text()) or {}
        robot = urdf.parse(d / meta.get("urdf", "robot.urdf"))
        params = load_params(d / meta.get("params", "params.yaml"))
        graph = Graph.load(d / meta.get("graph", "graph.json"))
        roles = {name: node_role(name, params.get(name, {})) for name in sorted(set(graph.nodes) | set(params))}
        arm_cfg = meta.get("arm")
        arm = urdf.arm_envelope(robot, arm_cfg["urdf_root"], arm_cfg["urdf_tip"]) if arm_cfg else None
        return cls(key or d.name, d, meta, robot, params, graph, roles, arm)

    # ---- masses and limits

    @property
    def name(self) -> str:
        return str(self.meta.get("model", self.key))

    @property
    def payload(self) -> float:
        return float(self.meta.get("payload_kg", 0.0))

    @property
    def base_mass(self) -> float:
        return self.robot.total_mass + self.payload

    @property
    def base_controller(self) -> str:
        return _norm(self.meta["base"]["controller"])

    def base_hardware_speed(self) -> float:
        """What the base can do if a command reaches its controller unfiltered."""
        p = self.params.get(self.base_controller, {})
        if p.get("linear.x.has_velocity_limits") and p.get("linear.x.max_velocity") is not None:
            return float(p["linear.x.max_velocity"])
        return float(self.meta["base"]["hardware_max_speed_mps"])

    def limiter_speed(self, node: str) -> float | None:
        p = self.params.get(node, {})
        role = self.roles.get(node)
        if role == "velocity_smoother":
            return _first(p.get("max_velocity"))
        if role == "controller_server":
            vals = [float(v) for k, v in p.items() if k.endswith(".max_vel_x")]
            return min(vals) if vals else None
        return None

    def moveit_scaling(self) -> float:
        for node, role in self.roles.items():
            if role == "move_group":
                return float(self.params.get(node, {}).get("default_velocity_scaling_factor", 1.0))
        return 1.0

    def moveit_node(self) -> str | None:
        return next((n for n, r in self.roles.items() if r == "move_group"), None)

    # ---- velocity dataflow

    def twist_paths(self, entry_topic: str) -> list[TwistPath]:
        """Every route a Twist on entry_topic can take to the base controller."""
        entry_topic = _norm(entry_topic)
        paths: list[TwistPath] = []
        queue: deque[tuple[str, list[str]]] = deque([(entry_topic, [])])
        seen: set[tuple[str, tuple[str, ...]]] = set()
        while queue:
            topic, via = queue.popleft()
            for sub in self.graph.subscribers_of(topic):
                if sub.name == self.base_controller:
                    paths.append(TwistPath(entry_topic, via))
                    continue
                if sub.name in via:
                    continue
                for pub in sub.publishers:
                    if pub.type in TWIST_TYPES:
                        state = (pub.name, (*via, sub.name))
                        if state not in seen:
                            seen.add(state)
                            queue.append((pub.name, [*via, sub.name]))
        return paths

    def nav_entry_topics(self) -> list[str]:
        """Velocity topics the navigation stack publishes (where planned motion enters)."""
        return [
            e.name
            for name, role in self.roles.items()
            if role == "controller_server" and name in self.graph.nodes
            for e in self.graph.nodes[name].publishers
            if e.type in TWIST_TYPES
        ]

    def safety_nodes(self) -> list[str]:
        return sorted(n for n, r in self.roles.items() if r in SAFETY_ROLES and n in self.graph.nodes)

    def summary(self) -> dict[str, Any]:
        return {
            "model": self.name,
            "urdf_mass_kg": round(self.robot.total_mass, 2),
            "payload_kg": self.payload,
            "base_hardware_speed_mps": self.base_hardware_speed(),
            "safety_nodes": self.safety_nodes(),
            "ros_security": self.graph.security_enabled,
            "arm": None
            if self.arm is None
            else {
                "joints": self.arm.joints,
                "reach_m": round(self.arm.reach_m, 3),
                "moving_mass_kg": round(self.arm.moving_mass_kg, 2),
                "tip_speed_bound_mps": round(self.arm.tip_speed_bound_mps, 3),
                "moveit_scaling": self.moveit_scaling(),
                "per_joint": self.arm.per_joint,
            },
        }
