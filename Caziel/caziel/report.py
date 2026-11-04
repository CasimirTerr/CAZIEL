"""Render an analysis as terminal text, Markdown, or JSON."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from . import __version__, analysis, cloud, edge, physics, ros, rules

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(stream: Any) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


# --------------------------------------------------------------------------- shared helpers


def worst_hit(res: analysis.ActorResult) -> str:
    ratio, actuator, region = res.worst_ratio()
    if ratio <= 0:
        return "no contact path"
    return (
        f"{actuator} → {region.replace('_', ' ')} {ratio:.0f}x"
        if ratio >= 1
        else f"{actuator} → {region.replace('_', ' ')} {ratio:.2f}x"
    )


def _layer(fleet: cloud.Fleet, part: str) -> str:
    if part.startswith(("iot:Publish", "greengrass:", "iot:CreateJob")):
        return "iot"
    if "." in part.split(" ", 1)[0] and part.split(".", 1)[0] in fleet.agents:
        return "agent"
    return "cloud"


def attack_path(fleet: cloud.Fleet, res: analysis.ActorResult, actuator: str | None = None) -> list[dict[str, str]]:
    """The most damaging chain for an actor (or for one actuator), from entry point to impact."""
    _ratio, worst_actuator, region = res.worst_ratio()
    actuator = actuator or worst_actuator
    if not res.reach or not actuator or actuator not in res.contact:
        return []
    if actuator != worst_actuator:
        region = max(res.exposure[actuator], key=lambda e: e.ratio).region
    thing = res.contact[actuator][1]
    reach = res.reach[thing]
    route = reach.worst(actuator)
    if route is None:
        return []
    group = fleet.group_of(thing)
    steps = [{"layer": "entry", "text": res.actor.entry}]
    # First the steps that prepare the route: parameter writes that lift speed caps or switch off safety zones.
    switched_off = [g for g in route.path if g in reach.disabled_guards]
    prepared = sorted(set(route.unlocked) | set(switched_off))
    if prepared and route.kind != "code":
        access = res.access[thing]
        for how in sorted({access.can_write_params(n) for n in prepared}):
            *lead, last = how.split(" → ")
            steps += [{"layer": _layer(fleet, part), "text": part} for part in lead]
            steps.append({"layer": "iot", "text": f"{last}: rewrites parameters on {', '.join(prepared)}"})
    # Then the command that moves the robot.
    seen = {s["text"] for s in steps}
    for part in route.how.split(" → "):
        if part not in seen or part.startswith("iot:"):
            steps.append({"layer": _layer(fleet, part), "text": part})
    if route.kind == "code":
        steps.append({"layer": "edge", "text": f"New software runs on {thing} with full hardware access"})
    else:
        steps.append({"layer": "edge", "text": f"{group.bridge.name} on {thing} turns it into {route.entry}"})
    ros_text = " → ".join(route.path)
    if route.bypassed_guards:
        ros_text += f" (never passes {', '.join(route.bypassed_guards)})"
    if prepared:
        ros_text += f" (caps and zones already lifted on {', '.join(prepared)})"
    steps.append({"layer": "ros", "text": ros_text})
    if route.contact_speed <= 0:
        why = []
        if route.gated:
            why.append("a human has to approve the command first")
        if route.actuator == "base" and route.active_guards:
            why.append(f"{', '.join(route.active_guards)} stops the base before it reaches a person")
        steps.append({"layer": "blocked", "text": "Blocked: " + "; ".join(why or ["no route to a person"])})
        return steps
    e = next(x for x in res.exposure[actuator] if x.region == region)
    steps.append(
        {
            "layer": "physical",
            "text": f"{actuator.capitalize()} reaches a person at {route.contact_speed:.2f} m/s: "
            f"{e.energy_j:.1f} J into the {e.label.lower()}, {e.ratio:.0f}x the {e.limit_j:.2f} J limit",
        }
    )
    return steps


def actor_dict(fleet: cloud.Fleet, res: analysis.ActorResult) -> dict[str, Any]:
    ratio, actuator, region = res.worst_ratio()
    worst_routes: list[edge.Route] = []
    for act, (_, thing) in res.contact.items():
        r = res.reach[thing].worst(act)
        if r:
            worst_routes.append(r)
    sample = res.contact.get("base", res.contact.get("arm", (0.0, "")))[1]
    return {
        "key": res.actor.key,
        "kind": res.actor.kind,
        "label": res.actor.label,
        "entry": res.actor.entry,
        "severity": res.severity,
        "robots_reachable": len(res.robots),
        "robots_moving": len(res.moving_robots),
        "things": res.moving_robots,
        "contact_speed_mps": {a: round(v[0], 3) for a, v in res.contact.items()},
        "worst": {"ratio": round(ratio, 2), "actuator": actuator, "region": region},
        "exposure": {a: [e.to_dict() for e in lst] for a, lst in res.exposure.items()},
        "routes": [r.to_dict() for r in res.reach[sample].routes] if sample else [],
        "worst_routes": [r.to_dict() for r in worst_routes],
        "disabled_guards": sorted(res.reach[sample].disabled_guards) if sample else [],
        "stoppable_guards": sorted(res.reach[sample].stoppable) if sample else [],
        "escalations": sorted(set(res.escalations)),
        "findings": [f.to_dict() for f in res.findings],
        "attack_path": attack_path(fleet, res),
        "attack_paths": {a: attack_path(fleet, res, a) for a in res.contact},
    }


def safe_speeds(fleet: cloud.Fleet, model: ros.RobotModel) -> dict[str, dict[str, float]]:
    out = {"base": {r: round(physics.safe_speed(fleet.region_table[r], model.base_mass), 3) for r in fleet.regions}}
    if model.arm:
        m = physics.arm_effective_mass(model.arm.moving_mass_kg, model.payload)
        out["arm"] = {r: round(physics.safe_speed(fleet.region_table[r], m), 3) for r in fleet.regions}
        out["arm_effective_mass_kg"] = {"value": round(m, 2)}
    return out


def to_dict(report: analysis.Report) -> dict[str, Any]:
    f = report.fleet
    worst = max(report.results, key=lambda r: r.worst_ratio()[0], default=None)
    return {
        "tool": "caziel",
        "version": __version__,
        "fleet": {
            "name": f.name,
            "account": f.account,
            "region": f.region,
            "robots": f.thing_count,
            "people_present": f.people_present,
            "body_regions": [
                f.region_table[r].__dict__ | {"energy_limit_j": round(f.region_table[r].energy_limit_j, 3)}
                for r in f.regions
            ],
            "models": [
                g.model.summary()
                | {
                    "things": g.things,
                    "bridge": g.bridge.name,
                    "base_mass_kg": round(g.model.base_mass, 2),
                    "safe_speed_mps": safe_speeds(f, g.model),
                }
                for g in f.groups
            ],
        },
        "summary": {
            "counts": report.counts(),
            "accepted": sum(1 for x in report.findings if x.accepted),
            "actors": len(report.results),
            "actors_that_move_robots": sum(1 for r in report.results if r.moving_robots),
            "actors_with_contact": sum(1 for r in report.results if r.worst_ratio()[0] > 0),
            "worst": None
            if worst is None or worst.worst_ratio()[0] == 0
            else {
                "actor": worst.actor.key,
                "ratio": round(worst.worst_ratio()[0], 2),
                "actuator": worst.worst_ratio()[1],
                "region": worst.worst_ratio()[2],
            },
        },
        "actors": [actor_dict(f, r) for r in report.results],
        "network": [x.to_dict() for x in report.network],
        "findings": [x.to_dict() for x in report.findings],
        "checks": {
            k: {"title": c.title, "severity": c.severity, "attack": list(c.attack)} for k, c in rules.CHECKS.items()
        },
    }


def to_json(report: analysis.Report) -> str:
    return json.dumps(to_dict(report), indent=2) + "\n"


# --------------------------------------------------------------------------- text


def to_text(report: analysis.Report, color: bool | None = None, stream: Any = None) -> str:
    color = _use_color(stream or sys.stdout) if color is None else color

    def c(key: str, s: str) -> str:
        return f"{COLORS[key]}{s}{COLORS['reset']}" if color else s

    f = report.fleet
    models = ", ".join(g.model.name for g in f.groups)
    out = [c("bold", f"Caziel {__version__}") + f"  {f.name}  ·  {f.thing_count} robots ({models})", ""]
    counts = report.counts()
    out.append(
        "  " + "   ".join(c(s, f"{s.upper()} {counts[s]}") for s in ("critical", "high", "medium", "low") if counts[s])
        or "  No open findings."
    )
    acc = sum(1 for x in report.findings if x.accepted)
    if acc:
        out.append(c("dim", f"  ({acc} accepted finding(s) not counted)"))
    out += ["", c("bold", "Who can move your robots"), ""]
    hdr = f"  {'ACTOR':<34}{'ROBOTS':>8}{'BASE m/s':>10}{'ARM m/s':>9}   {'WORST HIT':<24}SEVERITY"
    out.append(c("dim", hdr))
    for r in report.results:
        base = r.contact.get("base", (0.0, ""))[0]
        arm = r.contact.get("arm", (0.0, ""))[0]
        robots = f"{len(r.moving_robots)}/{f.thing_count}"
        line = f"  {r.actor.key:<34}{robots:>8}{base:>10.2f}{arm:>9.2f}   {worst_hit(r):<24}"
        out.append(line + c(r.severity, r.severity.upper()))
    out.append(
        c(
            "dim",
            "  Speeds are what the actor can make the robot reach a person at; 0 means a safety layer stops it first.",
        )
    )

    findings = report.open_findings
    if findings:
        out += ["", c("bold", "Findings"), ""]
    by_check: dict[str, list[analysis.Finding]] = {}
    for x in findings:
        by_check.setdefault(x.check, []).append(x)
    for check, group in by_check.items():
        chk = rules.CHECKS[check]
        sev = max((x.severity for x in group), key=lambda s: rules.SEVERITY_ORDER[s])
        out.append(f"  {c(sev, f'[{sev.upper()}]')} {check} {chk.title}")
        for x in group:
            robots = f" ({x.robots} robots)" if x.robots else ""
            out.append(f"    {c('bold', x.actor)}{robots}: {x.detail}")
            for ev in x.evidence[:2]:
                out.append(c("dim", f"      - {ev}"))
        out.append(f"    fix: {chk.fix}")
        out.append(c("dim", f"    maps to: {', '.join(chk.attack)}"))
        out.append("")

    worst = next(
        (r for r in report.results if r.worst_ratio()[0] > 1 and not all(x.accepted for x in r.findings)), None
    )
    if worst:
        out += [c("bold", f"Worst attack path: {worst.actor.key}"), ""]
        for i, step in enumerate(attack_path(f, worst), 1):
            out.append(f"  {i}. {c('dim', step['layer'].upper().ljust(9))}{step['text']}")
        out.append("")
    out.append(c("dim", "Estimates for prioritising security work, not a functional-safety assessment."))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- markdown


def to_markdown(report: analysis.Report) -> str:
    f = report.fleet
    counts = report.counts()
    lines = [
        f"# Caziel report: {f.name}",
        "",
        f"{f.thing_count} robots · account `{f.account}` · {f.region} · Caziel {__version__}",
        "",
        " · ".join(f"**{counts[s]} {s}**" for s in ("critical", "high", "medium", "low")),
        "",
        "## Who can move the robots",
        "",
        "| Actor | Entry | Robots | Base m/s | Arm m/s | Worst hit | Severity |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for r in report.results:
        lines.append(
            f"| `{r.actor.key}` | {r.actor.entry} | {len(r.moving_robots)}/{f.thing_count} | "
            f"{r.contact.get('base', (0.0, ''))[0]:.2f} | {r.contact.get('arm', (0.0, ''))[0]:.2f} | "
            f"{worst_hit(r)} | {r.severity} |"
        )
    lines += ["", "## Findings", ""]
    for x in report.findings:
        chk = rules.CHECKS[x.check]
        tag = " (accepted)" if x.accepted else ""
        lines += [
            f"### {x.check} · {x.severity}{tag}: {chk.title}",
            "",
            f"**Actor:** `{x.actor}`" + (f" · {x.robots} robots" if x.robots else ""),
            "",
            x.detail,
            "",
        ]
        lines += [f"- {e}" for e in x.evidence]
        if x.accepted:
            lines += ["", f"> Accepted: {x.accepted}"]
        lines += ["", f"**Fix:** {chk.fix}", "", f"**Maps to:** {', '.join(chk.attack)}", ""]
    worst = next((r for r in report.results if r.worst_ratio()[0] > 1), None)
    if worst:
        lines += ["## Worst attack path", ""]
        for i, step in enumerate(attack_path(f, worst), 1):
            lines.append(f"{i}. **{step['layer']}**: {step['text']}")
        lines.append("")
    return "\n".join(lines)


def compare_table(before: analysis.Report, after: analysis.Report) -> str:
    lines = ["| Actor | Robots it can hurt | Worst hit | Severity |", "|---|---|---|---|"]
    for b in before.results:
        a = next((x for x in after.results if x.actor.key == b.actor.key), None)
        if a is None or (not b.findings and not a.findings):
            continue

        def hurt(r: analysis.ActorResult) -> int:
            return sum(1 for t, rr in r.reach.items() if rr.contact_speed("base") > 0 or rr.contact_speed("arm") > 0)

        lines.append(
            f"| `{b.actor.key}` | {hurt(b)} → {hurt(a)} | {worst_hit(b)} → {worst_hit(a)} | "
            f"{b.severity} → {a.severity}{' (accepted)' if a.severity == 'info' and a.findings else ''} |"
        )
    return "\n".join(lines)
