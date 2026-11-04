"""The cloud side of a fleet: AWS identities, AI agents, and IoT settings.

A fleet directory looks like this:

    fleet.yaml            account, region, robots, site, IoT settings
    cloud/iam.json        principals and their identity policies
    cloud/agents.yaml     Bedrock AgentCore / Bedrock agents and their tools
    robots/<model>/       robot.yaml, robot.urdf, params.yaml, graph.json, bridge.yaml
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import edge, iam, physics, ros


@dataclass
class Principal:
    name: str
    arn: str
    kind: str
    purpose: str
    exposure: str
    policies: iam.PolicySet
    documents: list[dict[str, Any]]
    unique_id: str = ""  # AROA.../AIDA..., what IoT Core reports as principal()


@dataclass
class Tool:
    name: str
    publishes: str
    role: str
    function_arn: str
    description: str = ""


@dataclass
class Agent:
    name: str
    arn: str
    runtime: str
    role: str
    human_approval: bool
    untrusted_inputs: list[str]
    tools: list[Tool]


@dataclass
class RobotGroup:
    model: ros.RobotModel
    bridge: edge.Bridge
    things: list[str]
    thing_group: str


@dataclass
class Fleet:
    name: str
    directory: Path
    account: str
    region: str
    groups: list[RobotGroup]
    principals: dict[str, Principal]
    agents: dict[str, Agent]
    jobs_run_commands: bool
    greengrass: bool
    people_present: bool
    regions: list[str]
    region_table: dict[str, physics.BodyRegion] = field(default_factory=dict)
    accepted: list[dict[str, Any]] = field(default_factory=list)

    # ---- ARN helpers

    def topic_arn(self, topic: str) -> str:
        return f"arn:aws:iot:{self.region}:{self.account}:topic/{topic}"

    def thing_arn(self, thing: str) -> str:
        return f"arn:aws:iot:{self.region}:{self.account}:thing/{thing}"

    def thing_group_arn(self, group: str) -> str:
        return f"arn:aws:iot:{self.region}:{self.account}:thinggroup/{group}"

    @property
    def thing_count(self) -> int:
        return sum(len(g.things) for g in self.groups)

    def group_of(self, thing: str) -> RobotGroup:
        for g in self.groups:
            if thing in g.things:
                return g
        raise KeyError(thing)


def _things(spec: Any) -> list[str]:
    if isinstance(spec, list):
        return [str(t) for t in spec]
    if isinstance(spec, dict):
        prefix, count = str(spec["prefix"]), int(spec["count"])
        width = int(spec.get("width", 2))
        return [f"{prefix}{i:0{width}d}" for i in range(1, count + 1)]
    raise ValueError(f"cannot read thing list from {spec!r}")


def load(directory: str | Path) -> Fleet:
    d = Path(directory)
    if not (d / "fleet.yaml").exists():
        raise FileNotFoundError(f"{d}: no fleet.yaml (is this a Caziel fleet directory?)")
    cfg = yaml.safe_load((d / "fleet.yaml").read_text()) or {}

    groups = []
    for spec in cfg.get("robots", []):
        rdir = d / "robots" / spec["model"]
        model = ros.RobotModel.load(rdir, spec["model"])
        bridge = edge.Bridge.load(rdir / model.meta.get("bridge", "bridge.yaml"))
        groups.append(RobotGroup(model, bridge, _things(spec["things"]), spec.get("thing_group", spec["model"])))

    principals: dict[str, Principal] = {}
    iam_path = d / cfg.get("identities", "cloud/iam.json")
    for raw in json.loads(iam_path.read_text()).get("principals", []):
        docs = raw.get("policies", [])
        principals[raw["name"]] = Principal(
            name=raw["name"],
            arn=raw.get("arn", ""),
            kind=raw.get("kind", "role"),
            purpose=raw.get("purpose", ""),
            exposure=raw.get("exposure", ""),
            policies=iam.PolicySet(docs),
            documents=docs,
            unique_id=raw.get("unique_id", ""),
        )

    agents: dict[str, Agent] = {}
    agents_path = d / cfg.get("agents", "cloud/agents.yaml")
    if agents_path.exists():
        for raw in (yaml.safe_load(agents_path.read_text()) or {}).get("agents", []):
            tools = [
                Tool(t["name"], t["publishes"], t["role"], t.get("function", ""), t.get("description", ""))
                for t in raw.get("tools", [])
            ]
            for t in tools:
                if t.role not in principals:
                    raise ValueError(f"agent {raw['name']}: tool {t.name} uses unknown role {t.role!r}")
            agents[raw["name"]] = Agent(
                name=raw["name"],
                arn=raw.get("arn", ""),
                runtime=raw.get("runtime", "bedrock-agentcore"),
                role=raw.get("role", ""),
                human_approval=bool(raw.get("human_approval", False)),
                untrusted_inputs=list(raw.get("untrusted_inputs", [])),
                tools=tools,
            )

    site = cfg.get("site", {})
    iot = cfg.get("iot", {})
    regions = list(site.get("body_regions", ["hand", "forearm", "chest", "abdomen", "thigh"]))
    table = physics.region_table(site.get("body_region_overrides"))
    for r in regions:
        if r not in table:
            raise ValueError(f"fleet.yaml: unknown body region {r!r}")
    return Fleet(
        name=cfg.get("name", d.name),
        directory=d,
        account=str(cfg["account_id"]),
        region=cfg["region"],
        groups=groups,
        principals=principals,
        agents=agents,
        jobs_run_commands=str((iot.get("jobs") or {}).get("handler", "none")) == "shell",
        greengrass=bool((iot.get("greengrass") or {}).get("enabled", False)),
        people_present=bool(site.get("people_present", True)),
        regions=regions,
        region_table=table,
        accepted=list(cfg.get("accepted_risks") or []),
    )
