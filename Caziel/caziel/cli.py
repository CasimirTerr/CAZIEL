"""Command line interface.

caziel scan FLEET [-f text|json|md] [-o FILE] [--fail-on SEVERITY]
caziel fix FLEET -o OUT
caziel robot ROBOT_DIR [--regions hand,chest,...]
caziel checks
caziel snapshot -o graph.json [--params params.yaml]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, analysis, cloud, physics, policy, report, ros, rules


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text)
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_scan(args: argparse.Namespace) -> int:
    fleet = cloud.load(args.fleet)
    rep = analysis.analyze(fleet)
    if args.format == "json":
        _write(report.to_json(rep), args.output)
    elif args.format == "md":
        _write(report.to_markdown(rep), args.output)
    else:
        _write(report.to_text(rep, color=False if args.no_color or args.output else None), args.output)
    if args.fail_on:
        hit = [f for f in rep.open_findings if rules.severity_at_least(f.severity, args.fail_on)]
        if hit:
            print(f"caziel: {len(hit)} open finding(s) at or above {args.fail_on}", file=sys.stderr)
            return 2
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    plan, before, after = policy.fix(args.fleet, args.output)
    print(f"Hardened fleet written to {args.output} ({len(plan.changes)} changes)\n")
    print(report.compare_table(before, after))
    print(f"\nDetails: {Path(args.output) / 'caziel-fix' / 'CHANGES.md'}")
    if plan.manual:
        print("\nStill to do by hand:")
        for m in plan.manual:
            print(f"  - {m}")
    return 0


def cmd_robot(args: argparse.Namespace) -> int:
    model = ros.RobotModel.load(args.robot)
    regions = args.regions.split(",") if args.regions else list(physics.BODY_REGIONS)
    summary = model.summary()
    summary["base_mass_kg"] = round(model.base_mass, 2)
    summary["base_safe_speed_mps"] = {
        r: round(physics.safe_speed(physics.BODY_REGIONS[r], model.base_mass), 3) for r in regions
    }
    if model.arm:
        m = physics.arm_effective_mass(model.arm.moving_mass_kg, model.payload)
        summary["arm_effective_mass_kg"] = round(m, 2)
        summary["arm_safe_speed_mps"] = {r: round(physics.safe_speed(physics.BODY_REGIONS[r], m), 3) for r in regions}
    for topic in sorted(model.graph.topics()):
        if model.graph.topic_type(topic) in ros.TWIST_TYPES:
            for p in model.twist_paths(topic):
                guards = p.through(model.roles, ros.SAFETY_ROLES)
                summary.setdefault("velocity_paths", []).append({"entry": topic, "via": p.nodes, "guarded_by": guards})
    _write(json.dumps(summary, indent=2) + "\n", args.output)
    return 0


def cmd_checks(args: argparse.Namespace) -> int:
    for c in rules.CHECKS.values():
        print(f"{c.id}  {c.severity:<8}  {c.title}")
        print(f"          {', '.join(c.attack)}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from . import live

    watcher = live.Watcher(cloud.load(args.fleet))
    stream = sys.stdin if args.events == "-" else open(args.events)  # noqa: SIM115
    floor = args.min_severity
    counts = {k: 0 for k in rules.SEVERITY_ORDER}
    color = not args.no_color and report._use_color(sys.stdout)
    try:
        for v in watcher.watch(live.read_events(stream)):
            counts[v.severity] += 1
            if not rules.severity_at_least(v.severity, floor):
                continue
            if args.json:
                print(json.dumps(v.to_dict()), flush=True)
            else:
                line = live.format_line(v)
                print(f"{report.COLORS[v.severity]}{line}{report.COLORS['reset']}" if color else line, flush=True)
    finally:
        if stream is not sys.stdin:
            stream.close()
    summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n)
    print(f"caziel watch: {sum(counts.values())} events ({summary})", file=sys.stderr)
    if args.fail_on and any(n and rules.severity_at_least(k, args.fail_on) for k, n in counts.items()):
        return 2
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    from . import snapshot

    return snapshot.main(args.output, args.params)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="caziel", description="Cloud-to-physical blast radius for AI-controlled robot fleets."
    )
    p.add_argument("--version", action="version", version=f"caziel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analyze a fleet directory")
    s.add_argument("fleet")
    s.add_argument("-f", "--format", choices=["text", "json", "md"], default="text")
    s.add_argument("-o", "--output")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="write a hardened copy of the fleet and re-check it")
    f.add_argument("fleet")
    f.add_argument("-o", "--output", required=True)
    f.set_defaults(func=cmd_fix)

    r = sub.add_parser("robot", help="physical envelope and velocity paths for one robot")
    r.add_argument("robot")
    r.add_argument("--regions")
    r.add_argument("-o", "--output")
    r.set_defaults(func=cmd_robot)

    w = sub.add_parser("watch", help="classify live AWS IoT Core commands (JSON lines) as they arrive")
    w.add_argument("fleet")
    w.add_argument("events", nargs="?", default="-", help="file of IoT rule output, or - for stdin (default)")
    w.add_argument("--min-severity", choices=list(rules.SEVERITY_ORDER), default="medium")
    w.add_argument("--json", action="store_true")
    w.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    w.add_argument("--no-color", action="store_true")
    w.set_defaults(func=cmd_watch)

    c = sub.add_parser("checks", help="list the checks Caziel runs")
    c.set_defaults(func=cmd_checks)

    n = sub.add_parser("snapshot", help="capture graph.json from a running ROS 2 system")
    n.add_argument("-o", "--output", default="graph.json")
    n.add_argument("--params")
    n.set_defaults(func=cmd_snapshot)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, FileExistsError, ValueError, KeyError) as exc:
        print(f"caziel: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
