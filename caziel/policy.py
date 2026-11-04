"""Generate the fix: a hardened copy of the fleet directory, plus the policy artifacts.

`caziel fix FLEET -o OUT` writes OUT as a complete fleet directory that Caziel can scan
again, so every change can be checked by re-running the analysis. It also writes:

    OUT/caziel-fix/CHANGES.md                 what changed, why, and what is still manual
    OUT/caziel-fix/scp-fleet-guardrail.json   an Organizations SCP version of the IAM guardrail
    OUT/caziel-fix/sros2/<model>.policy.xml   SROS2 permissions for the bridge enclave

Fixes are deliberately conservative. Caziel keeps legitimate workflows working where it can
(a "nudge" stays possible, but routed through the collision monitor) and removes an
interface only when no safe version exists.
"""

from __future__ import annotations

import json
import math
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import analysis, cloud, physics, ros

RELEASE_TAG = "caziel:role"
GUARDRAIL_SID = "CazielFleetGuardrail"


@dataclass
class Change:
    area: str
    target: str
    what: str
    why: str


@dataclass
class FixPlan:
    changes: list[Change] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)

    def add(self, area: str, target: str, what: str, why: str) -> None:
        self.changes.append(Change(area, target, what, why))


def _floor(x: float, step: float = 0.05) -> float:
    return math.floor(x / step) * step


def _dump_yaml(path: Path, data: Any, header: str) -> None:
    path.write_text(header + yaml.safe_dump(data, sort_keys=False, default_flow_style=None))


def safe_base_speed(fleet: cloud.Fleet, model: ros.RobotModel) -> tuple[float, str]:
    """Lowest safe speed across the fleet's body regions, for the whole base."""
    best = min(
        ((physics.safe_speed(fleet.region_table[r], model.base_mass), r) for r in fleet.regions),
        key=lambda x: x[0],
    )
    return best


def safe_arm_scaling(fleet: cloud.Fleet, model: ros.RobotModel) -> tuple[float, str]:
    assert model.arm is not None
    mass = physics.arm_effective_mass(model.arm.moving_mass_kg, model.payload)
    v, region = min(((physics.safe_speed(fleet.region_table[r], mass), r) for r in fleet.regions), key=lambda x: x[0])
    return v / model.arm.tip_speed_bound_mps, region


# --------------------------------------------------------------------------- robot side


def _fix_bridge(fleet: cloud.Fleet, group: cloud.RobotGroup, raw: dict[str, Any], plan: FixPlan) -> set[str]:
    """Rewrite bridge.yaml in place (raw dict). Returns the MQTT templates that were removed."""
    model = group.model
    removed: set[str] = set()
    safety = set(model.safety_nodes())
    cm_in = None
    for node in safety:
        topic = model.params.get(node, {}).get("cmd_vel_in_topic")
        if topic:
            cm_in = ros._norm(str(topic))
    lifecycle_nodes = sorted(
        n.name
        for n in model.graph.nodes.values()
        if any(s.name.endswith("/change_state") for s in n.services) and n.name not in safety
    )

    kept = []
    for m in raw.get("mappings", []):
        target = m.get("ros", {})
        kind, name, typ = target.get("kind"), ros._norm(target.get("name", "x")), target.get("type", "")
        mqtt = m["mqtt"]
        if kind == "topic" and typ in ros.TWIST_TYPES:
            paths = model.twist_paths(name)
            if any(set(safety) - set(p.nodes) for p in paths) and cm_in:
                target["name"] = cm_in
                m["requires_approval"] = True
                plan.add(
                    "bridge",
                    f"{group.bridge.name}: {mqtt}",
                    f"Retargeted from {name} to {cm_in} and set requires_approval",
                    "Commands on this mapping now pass through the collision monitor, so a nudge still "
                    "works but cannot drive into a person.",
                )
            elif any(set(safety) - set(p.nodes) for p in paths):
                removed.add(mqtt)
                plan.add(
                    "bridge",
                    f"{group.bridge.name}: {mqtt}",
                    "Removed",
                    "Raw velocity reaches the base without a safety node and there is no guarded topic to point it at.",
                )
                continue
        elif (kind == "topic" and typ == ros.TRAJECTORY_TOPIC) or (kind == "action" and typ == ros.TRAJECTORY_ACTION):
            removed.add(mqtt)
            plan.add(
                "bridge",
                f"{group.bridge.name}: {mqtt}",
                "Removed",
                "Raw joint trajectories skip MoveIt. Replay taught motions through MoveIt "
                "(ExecuteTrajectory or MoveGroup) so collision checks and velocity scaling apply.",
            )
            continue
        elif kind == "parameters":
            removed.add(mqtt)
            plan.add(
                "bridge",
                f"{group.bridge.name}: {mqtt}",
                "Removed",
                "Wildcard parameter writes let a cloud message raise speed limits or disable collision "
                "zones. Use Nav2 speed filter zones for 'slow down in busy aisles' instead.",
            )
            continue
        elif kind == "lifecycle":
            nodes = target.get("nodes") or ["*"]
            if "*" in nodes or set(map(ros._norm, nodes)) & safety:
                target["nodes"] = lifecycle_nodes
                plan.add(
                    "bridge",
                    f"{group.bridge.name}: {mqtt}",
                    f"Limited lifecycle control to {len(lifecycle_nodes)} non-safety nodes",
                    "Operators can still restart a hung Nav2 node, but cannot shut down the collision monitor.",
                )
        elif kind == "action" and typ == ros.MOVEIT_ACTION and not m.get("requires_approval"):
            m["requires_approval"] = True
            plan.add(
                "bridge",
                f"{group.bridge.name}: {mqtt}",
                "Set requires_approval",
                "The arm can reach a person standing next to the robot, and MoveIt does not see people. "
                "A human confirms each pick near staff.",
            )
        kept.append(m)
    raw["mappings"] = kept

    if not (raw.get("ros_security") or {}).get("enabled"):
        raw["ros_security"] = {"enabled": True, "strategy": "Enforce", "enclave": f"/caziel/{model.key}_bridge"}
        plan.add(
            "robot",
            model.name,
            "Enabled SROS2 (Enforce) with a dedicated bridge enclave",
            "Without DDS security, anything on the warehouse network can publish to /cmd_vel directly.",
        )
    lan = raw.get("lan") or {}
    if lan.get("endpoint") and str(lan.get("auth", "none")) == "none":
        port = str(lan["endpoint"]).rsplit(":", 1)[-1]
        raw["lan"] = {"endpoint": f"127.0.0.1:{port}", "auth": "token"}
        plan.add(
            "robot",
            f"{group.bridge.name} rosbridge",
            f"Bound to 127.0.0.1:{port} with token auth",
            "The maintenance tablet reaches it through the authenticated bridge instead of the open LAN.",
        )
    return removed


def _fix_params(fleet: cloud.Fleet, model: ros.RobotModel, raw: dict[str, Any], plan: FixPlan) -> None:
    v_safe, region = safe_base_speed(fleet, model)
    cap = _floor(v_safe)
    label = fleet.region_table[region].label.lower()
    for node, role in model.roles.items():
        body = raw.get(node.lstrip("/"), {}).get("ros__parameters")
        if body is None:
            continue
        if role == "velocity_smoother" and isinstance(body.get("max_velocity"), list):
            old = float(body["max_velocity"][0])
            if old > cap:
                body["max_velocity"][0] = round(cap, 2)
                plan.add(
                    "params",
                    f"{model.name} {node}",
                    f"max_velocity[0] {old} → {cap:.2f} m/s",
                    f"{cap:.2f} m/s keeps a {model.base_mass:.0f} kg base inside the transient-contact limit "
                    f"for the {label} (safe speed {v_safe:.2f} m/s).",
                )
        if role == "controller_server":
            for plugin, cfg in body.items():
                if isinstance(cfg, dict) and float(cfg.get("max_vel_x", 0)) > cap:
                    old = cfg["max_vel_x"]
                    cfg["max_vel_x"] = round(cap, 2)
                    if "desired_linear_vel" in cfg:
                        cfg["desired_linear_vel"] = min(float(cfg["desired_linear_vel"]), round(cap, 2))
                    plan.add(
                        "params",
                        f"{model.name} {node}",
                        f"{plugin}.max_vel_x {old} → {cap:.2f} m/s",
                        "Same cap on the planner side, so the smoother is not the only thing holding it.",
                    )
        if role == "move_group" and model.arm is not None:
            scale, aregion = safe_arm_scaling(fleet, model)
            old = float(body.get("default_velocity_scaling_factor", 1.0))
            new = _floor(scale, 0.01)
            if old > new:
                body["default_velocity_scaling_factor"] = round(new, 2)
                plan.add(
                    "params",
                    f"{model.name} {node}",
                    f"default_velocity_scaling_factor {old} → {new:.2f}",
                    f"Keeps the tool tip under the safe speed for the {aregion.replace('_', ' ')}.",
                )
    plan.manual.append(
        f"{model.name}: the base controller still allows {model.base_hardware_speed():.1f} m/s. ROS parameters "
        "can be changed by anything that runs on the robot. Enforce the shared-zone speed limit in the motor "
        "drives or a safety PLC as well."
    )


def _project_graph(model: ros.RobotModel, path: Path, plan: FixPlan) -> None:
    data = json.loads(path.read_text())
    env = data.setdefault("environment", {})
    if str(env.get("ROS_SECURITY_ENABLE", "false")).lower() != "true":
        env["ROS_SECURITY_ENABLE"] = "true"
        env["ROS_SECURITY_STRATEGY"] = "Enforce"
        data["projected_by"] = "caziel fix (expected state once SROS2 is deployed; re-capture to confirm)"
        path.write_text(json.dumps(data, indent=2) + "\n")
        plan.manual.append(
            f"{model.name}: generate keys with `ros2 security create_keystore` and "
            f"`create_enclave`, then re-run `caziel snapshot` to confirm SROS2 is on."
        )


def sros2_policy(model: ros.RobotModel, bridge_raw: dict[str, Any]) -> str:
    """SROS2 permissions for the bridge enclave: only what the bridge mappings need."""
    topics_pub, actions, services = set(), set(), set()
    for m in bridge_raw.get("mappings", []):
        t = m.get("ros", {})
        name = ros._norm(t.get("name", "")).lstrip("/")
        if t.get("kind") == "topic":
            topics_pub.add(name)
        elif t.get("kind") == "action":
            actions.add(name)
        elif t.get("kind") == "lifecycle":
            for n in t.get("nodes", []):
                services.add(ros._norm(n).lstrip("/") + "/change_state")
    enclave = (bridge_raw.get("ros_security") or {}).get("enclave", f"/caziel/{model.key}_bridge")
    safety = sorted(n.lstrip("/") for n in model.safety_nodes())

    def block(tag: str, attr: str, names: set[str] | list[str], kind: str) -> str:
        if not names:
            return ""
        inner = "".join(f"\n            <{kind}>{n}</{kind}>" for n in sorted(names))
        return f"\n          <{tag} {attr}>{inner}\n          </{tag}>"

    deny = [*(f"{s}/change_state" for s in safety), *(f"{s}/set_parameters" for s in safety)]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<!-- Generated by caziel fix for {model.name}. Bridge enclave only. -->\n"
        '<policy version="0.2.0" xmlns:xi="http://www.w3.org/2001/XInclude">\n'
        "  <enclaves>\n"
        f'    <enclave path="{enclave}">\n'
        "      <profiles>\n"
        f'        <profile ns="/" node="{model.key}_edge_bridge">'
        + block("topics", 'publish="ALLOW"', topics_pub, "topic")
        + block("topics", 'subscribe="ALLOW"', {"odom", "collision_monitor_state"}, "topic")
        + block("actions", 'call="ALLOW"', actions, "action")
        + block("services", 'request="ALLOW"', services, "service")
        + block("topics", 'publish="DENY"', {"cmd_vel"} - topics_pub, "topic")
        + block("services", 'request="DENY"', deny, "service")
        + "\n        </profile>\n      </profiles>\n    </enclave>\n  </enclaves>\n</policy>\n"
    )


# --------------------------------------------------------------------------- cloud side


def _template_arn(fleet: cloud.Fleet, template: str) -> str:
    return fleet.topic_arn(template.replace("{thing}", "*"))


def _fix_iam(
    fleet: cloud.Fleet,
    report: analysis.Report,
    iam_raw: dict[str, Any],
    removed: set[str],
    kept_templates: set[str],
    plan: FixPlan,
) -> dict[str, Any]:
    tool_roles = {t.role for a in fleet.agents.values() for t in a.tools}
    tool_functions = sorted({t.function_arn for a in fleet.agents.values() for t in a.tools if t.function_arn})
    risky = {"CZL-001", "CZL-002", "CZL-003", "CZL-004", "CZL-005", "CZL-007"}
    accepted: dict[str, Any] = {}
    group_arns = [fleet.thing_group_arn(g.thing_group) for g in fleet.groups]
    thing_arn_glob = fleet.thing_arn("*")

    for raw in iam_raw["principals"]:
        name = raw["name"]
        res = next((r for r in report.results if r.actor.key == f"principal:{name}"), None)
        flagged = {f.check for f in res.findings} if res else set()
        is_release = (raw.get("tags") or {}).get(RELEASE_TAG) == "release"
        docs = raw.setdefault("policies", [])

        if name in tool_roles:
            allowed = sorted(
                _template_arn(fleet, t.publishes)
                for a in fleet.agents.values()
                for t in a.tools
                if t.role == name and t.publishes in kept_templates
            )
            if allowed:
                docs.append(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CazielToolScope",
                                "Effect": "Deny",
                                "Action": "iot:Publish",
                                "NotResource": allowed,
                            }
                        ],
                    }
                )
                plan.add(
                    "iam",
                    name,
                    f"Denied iot:Publish everywhere except {len(allowed)} tool topic(s)",
                    "The tool role could publish anywhere under fleet/*. Rewriting one tool's code would "
                    "have handed that over. Now the role can only send what the tools are written to send.",
                )

        if not flagged & risky:
            continue
        if is_release:
            accepted[name] = {
                "actor": f"principal:{name}",
                "checks": sorted(flagged & {"CZL-005", "CZL-008", "CZL-010"}),
                "reason": "Release pipeline has to deploy robot software. Accepted on the condition that "
                "components are signed and the OIDC trust is limited to the protected main branch.",
                "review_by": "set a date",
            }
            plan.manual.append(
                f"{name}: limit the OIDC trust policy to refs/heads/main and require signed "
                "Greengrass components. Caziel marked its code-deploy finding as accepted on "
                "that condition; check it is true."
            )
            continue
        statement: dict[str, Any] = {"Sid": GUARDRAIL_SID, "Effect": "Deny", "Action": [], "Resource": []}
        deny_topics = sorted(_template_arn(fleet, t) for t in removed)
        stmts = []
        if deny_topics:
            stmts.append(
                {**statement, "Sid": GUARDRAIL_SID + "Topics", "Action": "iot:Publish", "Resource": deny_topics}
            )
        stmts.append(
            {
                **statement,
                "Sid": GUARDRAIL_SID + "Code",
                "Action": ["greengrass:CreateDeployment", "iot:CreateJob"],
                "Resource": [*group_arns, thing_arn_glob],
            }
        )
        if tool_functions:
            stmts.append(
                {
                    **statement,
                    "Sid": GUARDRAIL_SID + "Tools",
                    "Action": ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"],
                    "Resource": tool_functions,
                }
            )
        docs.append({"Version": "2012-10-17", "Statement": stmts})
        plan.add(
            "iam",
            name,
            "Added explicit-deny guardrail (raw topics, code deploy, agent tool code)",
            f"{name} was flagged for {', '.join(sorted(flagged & risky))}.",
        )
    return accepted


def scp(fleet: cloud.Fleet, removed: set[str], release_roles: list[str]) -> dict[str, Any]:
    exempt = [f"arn:aws:iam::{fleet.account}:role/{r}" for r in release_roles]
    stmts: list[dict[str, Any]] = []
    if removed:
        stmts.append(
            {
                "Sid": "NoRawRobotControl",
                "Effect": "Deny",
                "Action": "iot:Publish",
                "Resource": sorted(_template_arn(fleet, t) for t in removed),
            }
        )
    code: dict[str, Any] = {
        "Sid": "OnlyReleaseDeploysRobotCode",
        "Effect": "Deny",
        "Action": ["greengrass:CreateDeployment", "iot:CreateJob"],
        "Resource": "*",
    }
    if exempt:
        code["Condition"] = {"ArnNotLike": {"aws:PrincipalArn": exempt}}
    stmts.append(code)
    return {"Version": "2012-10-17", "Statement": stmts}


# --------------------------------------------------------------------------- driver


def fix(src: str | Path, out: str | Path) -> tuple[FixPlan, analysis.Report, analysis.Report]:
    src, out = Path(src), Path(out)
    if out.exists():
        if not (out / "fleet.yaml").exists() and any(out.iterdir()):
            raise FileExistsError(f"{out} exists and is not a fleet directory; refusing to overwrite")
        shutil.rmtree(out)
    before_fleet = cloud.load(src)
    before = analysis.analyze(before_fleet)
    shutil.copytree(src, out)
    plan = FixPlan()

    removed: set[str] = set()
    all_templates: set[str] = set()
    for g in before_fleet.groups:
        rdir = out / "robots" / g.model.key
        bpath = rdir / g.model.meta.get("bridge", "bridge.yaml")
        braw = yaml.safe_load(bpath.read_text())
        all_templates |= {m["mqtt"] for m in braw.get("mappings", [])}
        removed |= _fix_bridge(before_fleet, g, braw, plan)
        _dump_yaml(bpath, braw, "# Hardened by caziel fix. See caziel-fix/CHANGES.md.\n")
        ppath = rdir / g.model.meta.get("params", "params.yaml")
        praw = yaml.safe_load(ppath.read_text())
        _fix_params(before_fleet, g.model, praw, plan)
        _dump_yaml(ppath, praw, "# Hardened by caziel fix. See caziel-fix/CHANGES.md.\n")
        _project_graph(g.model, rdir / g.model.meta.get("graph", "graph.json"), plan)
        sdir = out / "caziel-fix" / "sros2"
        sdir.mkdir(parents=True, exist_ok=True)
        (sdir / f"{g.model.key}.policy.xml").write_text(sros2_policy(g.model, braw))
    kept = all_templates - removed

    cfg_path = out / "fleet.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())

    # Agents: drop tools whose bridge mapping no longer exists.
    agents_path = out / cfg.get("agents", "cloud/agents.yaml")
    if agents_path.exists():
        araw = yaml.safe_load(agents_path.read_text())
        for a in araw.get("agents", []):
            keep = []
            for t in a.get("tools", []):
                if t["publishes"] in removed:
                    plan.add(
                        "agent",
                        f"{a['name']}.{t['name']}",
                        "Removed tool",
                        f"It published to {t['publishes']}, which the bridge no longer accepts.",
                    )
                else:
                    keep.append(t)
            a["tools"] = keep
        _dump_yaml(agents_path, araw, "# Hardened by caziel fix. See caziel-fix/CHANGES.md.\n")

    iam_path = out / cfg.get("identities", "cloud/iam.json")
    iam_raw = json.loads(iam_path.read_text())
    accepted = _fix_iam(before_fleet, before, iam_raw, removed, kept, plan)
    iam_path.write_text(json.dumps(iam_raw, indent=2) + "\n")

    jobs = (cfg.get("iot") or {}).get("jobs") or {}
    if jobs.get("handler") == "shell":
        cfg["iot"]["jobs"]["handler"] = "signed-documents"
        plan.add(
            "iot",
            "Jobs",
            "Job handler: shell → signed-documents",
            "A shell job handler turns iot:CreateJob into remote code execution on every robot.",
        )
    if accepted:
        cfg["accepted_risks"] = [*(cfg.get("accepted_risks") or []), *accepted.values()]
    _dump_yaml(cfg_path, cfg, "# Hardened by caziel fix. See caziel-fix/CHANGES.md.\n")

    release = [p["name"] for p in iam_raw["principals"] if (p.get("tags") or {}).get(RELEASE_TAG) == "release"]
    fixdir = out / "caziel-fix"
    fixdir.mkdir(exist_ok=True)
    (fixdir / "scp-fleet-guardrail.json").write_text(json.dumps(scp(before_fleet, removed, release), indent=2) + "\n")

    after = analysis.analyze(cloud.load(out))
    (fixdir / "CHANGES.md").write_text(changes_markdown(plan, before, after))
    return plan, before, after


def changes_markdown(plan: FixPlan, before: analysis.Report, after: analysis.Report) -> str:
    from . import report  # local import to avoid a cycle

    lines = [
        f"# Caziel fix: {before.fleet.name}",
        "",
        "Generated by `caziel fix`. Every change below was re-checked by scanning this directory again.",
        "",
        "## Before and after",
        "",
        report.compare_table(before, after),
        "",
        "## Changes",
        "",
        "| Area | Target | Change | Why |",
        "|---|---|---|---|",
    ]
    for c in plan.changes:
        lines.append(f"| {c.area} | `{c.target}` | {c.what} | {c.why} |")
    lines += ["", "## Still to do by hand", ""]
    lines += [f"- {m}" for m in plan.manual] or ["- Nothing."]
    lines += [
        "",
        "Caziel estimates physical risk to prioritise security work. It is not a functional-safety "
        "assessment and does not replace ISO 10218 / ISO/TS 15066 validation on the real cell.",
        "",
    ]
    return "\n".join(lines)


__all__ = ["FixPlan", "fix", "safe_arm_scaling", "safe_base_speed", "scp", "sros2_policy"]
