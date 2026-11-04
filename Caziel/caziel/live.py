"""Live monitoring: classify AWS IoT Core commands as they arrive.

The static scan answers "what *could* happen". `caziel watch` answers "is it happening".
It reads publish events, one JSON object per line, in the shape an AWS IoT rule produces:

    SELECT topic() AS topic, principal() AS principal, clientid() AS client_id,
           timestamp() AS ts, * AS payload FROM 'fleet/+/cmd/#'

and classifies each one with the same reach and physics model the scanner uses.
Each verdict says what the command does to the robot, whether a safety layer is on its
path, whether the sender's policy still allows it, and how much energy it could put
into a person at the speed it asked for.

Attribution: IoT reports IAM callers as "<unique id>:<session name>". Caziel maps the
unique ID back to a principal from iam.json, and a Lambda session name back to the
agent tool that runs as that function. So "AROA...:fleet-nudge" becomes
"dispatch-agent.nudge (as fleet-tools-role)".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import IO, Any

from . import cloud, edge, physics, ros


@dataclass
class Attribution:
    actor: str  # analysis actor key: principal:<name> or agent:<name>
    principal: str
    via: str  # human-readable "who sent this"


@dataclass
class Verdict:
    ts: int
    topic: str
    thing: str
    template: str
    actor: str
    via: str
    severity: str
    title: str
    detail: str
    actuator: str = ""
    speed_mps: float = 0.0
    contact_speed_mps: float = 0.0
    exposure: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "topic": self.topic,
            "thing": self.thing,
            "template": self.template,
            "actor": self.actor,
            "via": self.via,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "actuator": self.actuator,
            "speed_mps": round(self.speed_mps, 3),
            "contact_speed_mps": round(self.contact_speed_mps, 3),
            "exposure": self.exposure,
            "tags": self.tags,
        }


def _match(template: str, topic: str) -> str | None:
    """Return the thing name if topic fits the template, else None."""
    tparts, parts = template.split("/"), topic.split("/")
    if len(tparts) != len(parts):
        return None
    thing = None
    for t, p in zip(tparts, parts):
        if t == "{thing}":
            thing = p
        elif t != p:
            return None
    return thing


class Watcher:
    def __init__(self, fleet: cloud.Fleet):
        self.fleet = fleet
        self.by_id: dict[str, str] = {}
        for p in fleet.principals.values():
            for key in (p.unique_id, p.name):
                if key:
                    self.by_id[key] = p.name
        self.tool_by_function: dict[str, tuple[str, str]] = {}
        for a in fleet.agents.values():
            for t in a.tools:
                if t.function_arn:
                    self.tool_by_function[t.function_arn.rsplit(":", 1)[-1]] = (a.name, t.name)
        # Parameters already rewritten on each robot during this stream. A later motion command
        # on that robot is judged with those limits lifted.
        self.tampered: dict[str, set[str]] = {}

    # ---------------------------------------------------------------- attribution

    def attribute(self, principal: str) -> Attribution:
        ident, _, session = principal.partition(":")
        name = self.by_id.get(ident)
        if name is None and "/" in principal:  # an ARN
            parts = principal.split("/")
            name = next((self.by_id[p] for p in parts if p in self.by_id), None)
            session = parts[-1] if principal.startswith("arn:aws:sts") else session
        if name is None:
            return Attribution("unknown", principal, f"unknown principal {principal}")
        tool = self.tool_by_function.get(session)
        if tool:
            agent, tname = tool
            return Attribution(f"agent:{agent}", name, f"{agent}.{tname} (as {name})")
        who = f"{name} ({session})" if session else name
        return Attribution(f"principal:{name}", name, who)

    # ---------------------------------------------------------------- classification

    def classify(self, event: dict[str, Any]) -> Verdict:
        topic = str(event.get("topic", ""))
        ts = int(event.get("ts", 0))
        att = self.attribute(str(event.get("principal", "")))
        payload = event.get("payload") or {}
        v = self._route(topic, payload)
        v.ts, v.topic, v.actor, v.via = ts, topic, att.actor, att.via
        p = self.fleet.principals.get(att.principal)
        if v.thing and p is not None and not p.policies.allows("iot:Publish", self.fleet.topic_arn(topic)):
            v.tags = ["policy-denies"]
            v.title = "Denied by IAM"
            v.detail = f"{att.principal}'s policy does not allow this publish, so IoT Core rejects it."
            v.severity, v.contact_speed_mps, v.exposure = "info", 0.0, None
        elif att.actor == "unknown" and v.severity == "info" and v.thing:
            v.severity, v.title = "medium", "Command from an unknown principal"
            v.detail = f"{att.principal} is not in iam.json. {v.detail}".strip()
        if v.thing and "CZL-003" in v.tags:
            node = ros._norm(str(payload.get("node", "")))
            self.tampered.setdefault(v.thing, set()).add(node)
        return v

    def _route(self, topic: str, payload: dict[str, Any]) -> Verdict:
        for g in self.fleet.groups:
            for m in g.bridge.mappings:
                thing = _match(m.mqtt, topic)
                if thing is not None and thing in g.things:
                    return self._verdict(g, m, thing, payload)
        parts = topic.split("/")
        thing = parts[1] if len(parts) >= 3 else ""
        if any(thing in g.things for g in self.fleet.groups):
            return Verdict(
                0,
                topic,
                thing,
                _template_guess(topic),
                "",
                "",
                "info",
                "Dropped by the edge bridge",
                "No bridge mapping for this topic, so it never reaches ROS.",
                tags=["unmapped"],
            )
        return Verdict(0, topic, "", "", "", "", "info", "Not a fleet topic", "")

    def _verdict(self, g: cloud.RobotGroup, m: edge.Mapping, thing: str, payload: dict[str, Any]) -> Verdict:
        model = g.model
        base = Verdict(0, "", thing, m.mqtt, "", "", "info", "", "")
        safety = set(model.safety_nodes())
        if m.kind == "lifecycle":
            node = ros._norm(str(payload.get("node", "")))
            allowed = "*" in m.nodes or node in {ros._norm(n) for n in m.nodes}
            if node in safety and allowed:
                base.severity, base.title = "high", "Safety node shut down from the cloud"
                base.detail = (
                    f"{payload.get('transition', 'change_state')} on {node}. Navigation stops and the "
                    "collision monitor is no longer protecting this robot."
                )
                base.tags.append("CZL-002")
            else:
                base.title, base.detail = "Lifecycle command", f"{payload.get('transition', '')} on {node or '?'}"
                if not allowed:
                    base.title, base.detail = "Dropped by the edge bridge", f"{node} is not in the bridge allowlist."
            return base
        if m.kind == "parameters":
            node = ros._norm(str(payload.get("node", "")))
            role = model.roles.get(node, "other")
            if role in ros.SAFETY_ROLES | ros.LIMITER_ROLES | {"move_group"}:
                base.severity, base.title = "high", "Safety or speed limit rewritten"
                base.detail = f"{node} {payload.get('name', '?')} = {payload.get('value', '?')}"
                base.tags.append("CZL-003")
            else:
                base.title, base.detail = "Parameter write", f"{node} {payload.get('name', '')}"
            return base

        acc = edge.Access()
        acc.add(m, m.mqtt)
        for node in self.tampered.get(thing, ()):
            acc.param_nodes[node] = "earlier parameter write"
        r = edge.reach(model, acc)
        actuator = "arm" if any(x.actuator == "arm" for x in r.routes) else "base"
        route = r.worst(actuator)
        if route is None:
            base.title, base.detail = "Other command", f"{m.kind} {m.name} (no motion model for this interface)"
            return base
        base.actuator = actuator
        base.speed_mps = route.speed_mps
        if m.kind == "topic" and route.actuator == "base":
            asked = abs(float(((payload.get("linear") or {}).get("x", route.speed_mps)) or 0.0))
            base.speed_mps = min(asked, route.speed_mps)
        contact = 0.0 if route.contact_speed <= 0 else base.speed_mps
        base.contact_speed_mps = contact
        if route.gated:
            base.title = "Held for human approval"
            base.detail = f"{route.entry} needs a person to approve it before the robot moves."
            base.tags.append("gated")
            return base
        if contact <= 0:
            base.title = "Guarded motion"
            base.detail = (
                f"{route.entry} → {', '.join(route.active_guards) or 'planner'}. A safety layer stops it "
                "before it reaches a person."
            )
            return base
        mass = (
            model.base_mass
            if actuator == "base"
            else physics.arm_effective_mass(model.arm.moving_mass_kg, model.payload)
            if model.arm
            else 0.0
        )
        exps = physics.exposures(self.fleet.regions, mass, contact, self.fleet.region_table)
        worst = max(exps, key=lambda e: e.ratio)
        base.exposure = worst.to_dict()
        if route.bypassed_guards and actuator == "base":
            base.title, base.tags = "Velocity command skips the collision monitor", ["CZL-001"]
        elif route.kind == "raw":
            base.title, base.tags = "Raw arm trajectory, no MoveIt checks", ["CZL-004"]
        elif route.unlocked:
            base.title = "Motion with speed limits lifted"
        else:
            base.title = "Planned motion within limits" if worst.ratio <= 1 else "Unguarded motion"
        if worst.ratio >= 10 or (worst.ratio > 1 and "CZL-001" in base.tags):
            base.severity = "critical"
        elif worst.ratio > 1:
            base.severity = "high"
        else:
            # Under the limit. A path around the collision monitor is still worth a look.
            base.severity = "medium" if base.tags else "info"
        if route.unlocked:
            base.tags.append("limits-lifted")
        ratio = f"{worst.ratio:.0f}x" if worst.ratio >= 1 else f"{worst.ratio:.2f}x"
        base.detail = (
            f"{contact:.2f} m/s · up to {worst.energy_j:.1f} J into the {worst.label.lower()} ({ratio} the limit)"
        )
        return base

    def watch(self, events: Iterable[dict[str, Any]]) -> Iterator[Verdict]:
        for e in events:
            yield self.classify(e)


def _template_guess(topic: str) -> str:
    parts = topic.split("/")
    if len(parts) >= 2:
        parts[1] = "{thing}"
    return "/".join(parts)


def read_events(stream: IO[str]) -> Iterator[dict[str, Any]]:
    for n, line in enumerate(stream, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: not JSON ({exc.msg})") from exc


def format_line(v: Verdict) -> str:
    sev = v.severity.upper().ljust(8)
    return f"{sev} {v.topic:<34} {v.via:<44} {v.title}: {v.detail}"


__all__ = ["Attribution", "Verdict", "Watcher", "format_line", "read_events"]
