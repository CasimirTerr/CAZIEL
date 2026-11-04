"""Capture a ROS 2 graph from a running robot into Caziel's graph.json format.

Runs on the robot (or any machine on its ROS domain) with a sourced ROS 2 environment:

    caziel snapshot -o robots/kx1/graph.json --params robots/kx1/params.yaml

It only reads: `ros2 node list`, `ros2 node info`, and optionally `ros2 param dump`.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

SECTIONS = {
    "Subscribers:": "subscribers",
    "Publishers:": "publishers",
    "Service Servers:": "services",
    "Action Servers:": "action_servers",
    "Service Clients:": None,
    "Action Clients:": None,
}

# Infrastructure every node has; it only adds noise to the analysis.
NOISE = ("/parameter_events", "/rosout")
NOISE_SERVICES = (
    "/describe_parameters",
    "/get_parameter_types",
    "/get_parameters",
    "/list_parameters",
    "/set_parameters_atomically",
    "/get_type_description",
)


def parse_node_info(text: str) -> dict[str, Any]:
    """Parse the output of `ros2 node info <node>`."""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty node info")
    node: dict[str, Any] = {
        "name": lines[0].strip(),
        "publishers": [],
        "subscribers": [],
        "services": [],
        "action_servers": [],
    }
    section: str | None = None
    for ln in lines[1:]:
        s = ln.strip()
        if s in SECTIONS:
            section = SECTIONS[s]
            continue
        if section is None or ":" not in s:
            continue
        name, typ = (p.strip() for p in s.split(":", 1))
        if name in NOISE or (section == "services" and name.endswith(NOISE_SERVICES)):
            continue
        node[section].append({"name": name, "type": typ})
    return node


Runner = Callable[[list[str]], str]


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30).stdout


def capture(runner: Runner = _run, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if env is None else env)
    names = [n.strip() for n in runner(["ros2", "node", "list"]).splitlines() if n.strip().startswith("/")]
    nodes = []
    for name in sorted(set(names)):
        try:
            nodes.append(parse_node_info(runner(["ros2", "node", "info", name])))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
            nodes.append({"name": name, "error": str(exc)})
    keys = (
        "ROS_DOMAIN_ID",
        "ROS_SECURITY_ENABLE",
        "ROS_SECURITY_STRATEGY",
        "RMW_IMPLEMENTATION",
        "ROS_AUTOMATIC_DISCOVERY_RANGE",
    )
    return {
        "captured_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ros_distro": env.get("ROS_DISTRO", "unknown"),
        "environment": {k: env[k] for k in keys if k in env},
        "nodes": nodes,
    }


def dump_params(node_names: list[str], runner: Runner = _run) -> str:
    chunks = []
    for name in node_names:
        try:
            chunks.append(runner(["ros2", "param", "dump", name]))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
    return "\n".join(chunks)


def main(out: str, params_out: str | None = None) -> int:
    if shutil.which("ros2") is None:
        raise SystemExit("caziel snapshot: `ros2` not found. Source your ROS 2 setup.bash first.")
    data = capture()
    Path(out).write_text(json.dumps(data, indent=2) + "\n")
    if params_out:
        Path(params_out).write_text(dump_params([n["name"] for n in data["nodes"]]))
    print(f"captured {len(data['nodes'])} nodes → {out}")
    return 0
