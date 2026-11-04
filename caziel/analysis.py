"""Tie the cloud and the robots together: for every identity and every AI agent, work out
which robots it can move, how, and how hard.

The engine treats two kinds of actor:
  * a principal whose credentials leak (role session, access key, CI token)
  * an AI agent hijacked by indirect prompt injection through one of its untrusted inputs

and follows escalation edges between them: a principal that can invoke an agent, or rewrite
the Lambda behind one of its tools, inherits that reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import cloud, edge, physics, rules


@dataclass
class Finding:
    check: str
    actor: str
    severity: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    robots: int = 0
    accepted: str = ""  # reason, if the fleet owner accepted this risk

    @property
    def title(self) -> str:
        return rules.CHECKS[self.check].title

    def to_dict(self) -> dict[str, Any]:
        c = rules.CHECKS[self.check]
        return {
            "check": self.check,
            "title": c.title,
            "severity": self.severity,
            "actor": self.actor,
            "detail": self.detail,
            "evidence": self.evidence,
            "robots": self.robots,
            "attack": list(c.attack),
            "fix": c.fix,
            "accepted": self.accepted or None,
        }


@dataclass
class Actor:
    key: str
    kind: str  # principal | agent
    label: str
    entry: str


@dataclass
class ActorResult:
    actor: Actor
    access: dict[str, edge.Access]
    reach: dict[str, edge.Reach]
    escalations: list[str]
    findings: list[Finding] = field(default_factory=list)
    exposure: dict[str, list[physics.Exposure]] = field(default_factory=dict)
    contact: dict[str, tuple[float, str]] = field(default_factory=dict)  # actuator -> (m/s, thing)

    @property
    def robots(self) -> list[str]:
        return sorted(t for t, r in self.reach.items() if r.routes or r.stoppable or r.disabled_guards)

    @property
    def moving_robots(self) -> list[str]:
        return sorted(t for t, r in self.reach.items() if r.routes)

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.accepted]

    @property
    def severity(self) -> str:
        if not self.open_findings:
            return "info"
        return max((f.severity for f in self.open_findings), key=lambda s: rules.SEVERITY_ORDER[s])

    def worst_ratio(self) -> tuple[float, str, str]:
        best = (0.0, "", "")
        for actuator, exps in self.exposure.items():
            for e in exps:
                if e.ratio > best[0]:
                    best = (e.ratio, actuator, e.region)
        return best


# --------------------------------------------------------------------------- access resolution


class Resolver:
    def __init__(self, fleet: cloud.Fleet):
        self.fleet = fleet

    def _blank(self) -> dict[str, edge.Access]:
        return {t: edge.Access() for g in self.fleet.groups for t in g.things}

    def principal(
        self, name: str, prefix: str = "", seen: frozenset[str] = frozenset(), escalations: list[str] | None = None
    ) -> dict[str, edge.Access]:
        f = self.fleet
        p = f.principals[name]
        out = self._blank()
        esc = escalations if escalations is not None else []
        key = f"principal:{name}"
        if key in seen:
            return out
        seen = seen | {key}

        for g in f.groups:
            group_arn = f.thing_group_arn(g.thing_group)
            for thing in g.things:
                acc = out[thing]
                for m in g.bridge.mappings:
                    topic = m.topic_for(thing)
                    if p.policies.allows("iot:Publish", f.topic_arn(topic)):
                        acc.add(m, f"{prefix}iot:Publish {topic}")
                targets = (f.thing_arn(thing), group_arn)
                if f.greengrass and any(p.policies.allows("greengrass:CreateDeployment", t) for t in targets):
                    acc.code_exec = f"{prefix}greengrass:CreateDeployment on {g.thing_group}"
                elif f.jobs_run_commands and any(p.policies.allows("iot:CreateJob", t) for t in targets):
                    acc.code_exec = f"{prefix}iot:CreateJob with a shell job handler on {g.thing_group}"

        for agent in f.agents.values():
            if agent.arn and (
                p.policies.allows("bedrock-agentcore:InvokeAgentRuntime", agent.arn)
                or p.policies.allows("bedrock:InvokeAgent", agent.arn)
            ):
                step = f"{name} invokes agent {agent.name}"
                esc.append(step)
                self._merge(out, self.agent(agent.name, f"{prefix}{step} → ", seen, esc, injected=False))
            for tool in agent.tools:
                if tool.function_arn and p.policies.allows("lambda:UpdateFunctionCode", tool.function_arn):
                    fn = tool.function_arn.rsplit(":", 1)[-1]
                    step = f"{name} rewrites Lambda {fn} (runs as {tool.role})"
                    esc.append(step)
                    self._merge(out, self.principal(tool.role, f"{prefix}{step} → ", seen, esc))
        return out

    def agent(
        self,
        name: str,
        prefix: str = "",
        seen: frozenset[str] = frozenset(),
        escalations: list[str] | None = None,
        injected: bool = True,
    ) -> dict[str, edge.Access]:
        f = self.fleet
        a = f.agents[name]
        out = self._blank()
        key = f"agent:{name}"
        if key in seen:
            return out
        for g in f.groups:
            by_template = {m.mqtt: m for m in g.bridge.mappings}
            for thing in g.things:
                acc = out[thing]
                for tool in a.tools:
                    m = by_template.get(tool.publishes)
                    if m is None:
                        continue
                    topic = m.topic_for(thing)
                    if f.principals[tool.role].policies.allows("iot:Publish", f.topic_arn(topic)):
                        acc.add(m, f"{prefix}{a.name}.{tool.name} → iot:Publish {topic}")
                        if a.human_approval and m.name:
                            acc.gated.add(edge.ros._norm(m.name))
        return out

    @staticmethod
    def _merge(into: dict[str, edge.Access], other: dict[str, edge.Access]) -> None:
        for thing, acc in other.items():
            into[thing].merge(acc)


# --------------------------------------------------------------------------- findings


def _findings(fleet: cloud.Fleet, res: ActorResult) -> list[Finding]:
    out: list[Finding] = []
    actor = res.actor.key
    total = fleet.thing_count

    def robots_where(pred: Any) -> list[str]:
        return sorted(t for t, r in res.reach.items() if pred(t, r))

    direct = robots_where(
        lambda t, r: any(
            x.actuator == "base" and x.kind == "direct" and x.bypassed_guards and x.contact_speed > 0 for x in r.routes
        )
    )
    if direct:
        r = res.reach[direct[0]]
        route = max((x for x in r.routes if x.kind == "direct" and x.contact_speed > 0), key=lambda x: x.speed_mps)
        out.append(
            Finding(
                "CZL-001",
                actor,
                "critical",
                f"{route.entry} reaches the base controller without passing "
                f"{', '.join(route.bypassed_guards)} ({route.speed_mps:.2f} m/s).",
                [route.how, " → ".join(route.path)],
                len(direct),
            )
        )

    stop = robots_where(lambda t, r: bool(r.stoppable) and not r.code_exec)
    if stop:
        r = res.reach[stop[0]]
        out.append(
            Finding(
                "CZL-002",
                actor,
                "high",
                f"Can deactivate {', '.join(r.stoppable)} on {len(stop)} robots.",
                sorted(set(r.stoppable.values())),
                len(stop),
            )
        )

    params = robots_where(
        lambda t, r: not r.code_exec and (bool(r.disabled_guards) or any(x.unlocked for x in r.routes))
    )
    if params:
        r = res.reach[params[0]]
        nodes = sorted(set(r.disabled_guards) | {n for x in r.routes for n in x.unlocked})
        hows = sorted({res.access[params[0]].can_write_params(n) for n in nodes})
        out.append(
            Finding("CZL-003", actor, "high", f"Can rewrite parameters on {', '.join(nodes)}.", hows, len(params))
        )

    raw_arm = robots_where(
        lambda t, r: any(x.actuator == "arm" and x.kind == "raw" and x.contact_speed > 0 for x in r.routes)
    )
    if raw_arm:
        r = res.reach[raw_arm[0]]
        route = next(x for x in r.routes if x.actuator == "arm" and x.kind == "raw" and x.contact_speed > 0)
        out.append(
            Finding(
                "CZL-004",
                actor,
                "high",
                f"Raw trajectories on {route.entry} can move the tool tip at up to {route.speed_mps:.2f} m/s.",
                [route.how],
                len(raw_arm),
            )
        )

    code = robots_where(lambda t, r: bool(r.code_exec))
    if code:
        out.append(
            Finding(
                "CZL-005",
                actor,
                "critical",
                f"Can push software to {len(code)} robots.",
                sorted({res.reach[t].code_exec for t in code})[:3],
                len(code),
            )
        )

    if res.actor.kind == "agent":
        a = fleet.agents[actor.split(":", 1)[1]]
        ungated = robots_where(lambda t, r: any(x.contact_speed > 0 for x in r.routes))
        if a.untrusted_inputs and ungated and not a.human_approval:
            out.append(
                Finding(
                    "CZL-006",
                    actor,
                    "critical" if direct else "high",
                    f"{a.name} reads {len(a.untrusted_inputs)} untrusted input(s) and can move "
                    f"{len(ungated)} robots with no human approval.",
                    a.untrusted_inputs,
                    len(ungated),
                )
            )

    if res.escalations:
        out.append(
            Finding(
                "CZL-007",
                actor,
                "high",
                "Inherits reach through an AI agent or its tools.",
                sorted(set(res.escalations)),
                len(res.moving_robots),
            )
        )

    moving = res.moving_robots
    if total and len(moving) >= max(2, total // 2):
        out.append(Finding("CZL-008", actor, "medium", f"Can move {len(moving)} of {total} robots.", [], len(moving)))

    ratio, actuator, region = res.worst_ratio()
    if ratio > 1.0:
        e = next(x for x in res.exposure[actuator] if x.region == region)
        over = [x for exps in res.exposure.values() for x in exps if x.ratio > 1.0]
        regions = sorted({x.label for x in over})
        out.append(
            Finding(
                "CZL-010",
                actor,
                "critical" if ratio >= 10 else "high",
                f"Worst case: {actuator} into the {e.label.lower()} at "
                f"{res.contact[actuator][0]:.2f} m/s transfers "
                f"{e.energy_j:.1f} J against a {e.limit_j:.2f} J limit ({ratio:.0f}x).",
                [
                    f"Over the limit: {', '.join(regions)}",
                    f"Safe speed for this body region: {e.safe_speed_mps:.2f} m/s",
                ],
                len(moving),
            )
        )
    return out


def _network_findings(fleet: cloud.Fleet) -> list[Finding]:
    out = []
    for g in fleet.groups:
        if not g.model.graph.security_enabled and g.bridge.lan_endpoint and g.bridge.lan_auth == "none":
            out.append(
                Finding(
                    "CZL-009",
                    f"network:{g.model.key}",
                    "high",
                    f"{g.model.name}: SROS2 off and rosbridge open on {g.bridge.lan_endpoint}.",
                    [
                        f"ROS_SECURITY_ENABLE=false, domain {g.model.graph.domain_id}",
                        f"rosbridge auth: {g.bridge.lan_auth}",
                    ],
                    len(g.things),
                )
            )
    return out


# --------------------------------------------------------------------------- top level


@dataclass
class Report:
    fleet: cloud.Fleet
    results: list[ActorResult]
    network: list[Finding]

    @property
    def findings(self) -> list[Finding]:
        all_f = [f for r in self.results for f in r.findings] + self.network
        return sorted(all_f, key=lambda f: (-rules.SEVERITY_ORDER[f.severity], f.check, f.actor))

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.accepted]

    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in rules.SEVERITY_ORDER}
        for f in self.open_findings:
            c[f.severity] += 1
        return c

    def result(self, key: str) -> ActorResult:
        return next(r for r in self.results if r.actor.key == key)


def _actors(fleet: cloud.Fleet) -> list[Actor]:
    actors = []
    for a in fleet.agents.values():
        if a.untrusted_inputs:
            entry = "Indirect prompt injection via " + "; ".join(a.untrusted_inputs)
        else:
            entry = "Prompt injection by a user of the agent"
        actors.append(Actor(f"agent:{a.name}", "agent", a.name, entry))
    for p in fleet.principals.values():
        entry = f"Stolen credentials ({p.exposure})" if p.exposure else "Stolen credentials"
        actors.append(Actor(f"principal:{p.name}", "principal", p.name, entry))
    return actors


def analyze(fleet: cloud.Fleet) -> Report:
    resolver = Resolver(fleet)
    results = []
    for actor in _actors(fleet):
        escalations: list[str] = []
        name = actor.key.split(":", 1)[1]
        if actor.kind == "agent":
            access = resolver.agent(name, escalations=escalations)
        else:
            access = resolver.principal(name, escalations=escalations)

        reach: dict[str, edge.Reach] = {}
        for g in fleet.groups:
            for thing in g.things:
                acc = access[thing]
                if not acc.empty():
                    reach[thing] = edge.reach(g.model, acc)

        res = ActorResult(actor, access, reach, escalations)
        # Worst body-region exposure per actuator across all reachable robots.
        for thing in sorted(reach):
            r = reach[thing]
            exps = edge.exposures_for(fleet.group_of(thing).model, r, fleet.regions, fleet.region_table)
            for actuator, lst in exps.items():
                cur = res.exposure.get(actuator)
                if cur is None or max(e.energy_j for e in lst) > max(e.energy_j for e in cur):
                    res.exposure[actuator] = lst
                    res.contact[actuator] = (r.contact_speed(actuator), thing)
        res.findings = _findings(fleet, res) if reach else []
        _apply_accepted(fleet, res.findings)
        results.append(res)
    _settle_escalations(results)
    results.sort(key=lambda r: (-rules.SEVERITY_ORDER[r.severity], -r.worst_ratio()[0], r.actor.key))
    network = _network_findings(fleet)
    _apply_accepted(fleet, network)
    return Report(fleet, results, network)


def _settle_escalations(results: list[ActorResult]) -> None:
    """Invoking an agent is normal use. It only counts as an escalation when the agent itself is dangerous.

    Rewriting a tool's code is never normal use, so those edges always stay.
    """
    agent_sev = {r.actor.label: r.severity for r in results if r.actor.kind == "agent"}
    for r in results:
        if not r.escalations:
            continue
        keep = []
        for step in r.escalations:
            if " invokes agent " in step:
                agent = step.split(" invokes agent ", 1)[1]
                if not rules.severity_at_least(agent_sev.get(agent, "info"), "high"):
                    continue
            keep.append(step)
        r.escalations = keep
        if not keep:
            r.findings = [f for f in r.findings if f.check != "CZL-007"]
        else:
            for f in r.findings:
                if f.check == "CZL-007":
                    f.evidence = sorted(set(keep))


def _apply_accepted(fleet: cloud.Fleet, findings: list[Finding]) -> None:
    for entry in fleet.accepted:
        checks = set(entry.get("checks") or [entry.get("check")])
        for f in findings:
            if f.actor == entry.get("actor") and (f.check in checks or "*" in checks):
                f.accepted = str(entry.get("reason", "accepted"))
