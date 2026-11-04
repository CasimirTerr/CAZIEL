"""The checks Caziel runs, with their severity, framework mappings, and fixes.

Every finding in a report points back to one of these entries, and CHECKS.md is generated
from this table (scripts/gen_checks_doc.py) so the docs cannot drift from the code.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    why: str
    fix: str
    attack: tuple[str, ...] = ()  # MITRE ATT&CK (Enterprise, ICS) and ATLAS technique IDs


CHECKS: dict[str, Check] = {
    c.id: c
    for c in (
        Check(
            "CZL-001",
            "Cloud identity can drive the base around the collision monitor",
            "critical",
            "Velocity commands from the cloud land on a topic downstream of the robot's collision monitor, so "
            "the node that is supposed to stop the robot before it hits someone never sees them.",
            "Remove raw velocity from the edge bridge, or point it at the collision monitor's input topic. "
            "Deny iot:Publish on fleet/*/cmd/velocity for every role that does not need teleoperation.",
            ("T0855", "T0880"),
        ),
        Check(
            "CZL-002",
            "Cloud identity can shut down a safety node",
            "high",
            "Lifecycle transitions are exposed through the bridge, so a cloud message can deactivate the "
            "collision monitor. That halts navigation for the whole fleet and removes the safety layer.",
            "Do not bridge lifecycle services. Use SROS2 to deny change_state on safety nodes to the bridge enclave.",
            ("T0813", "T0880"),
        ),
        Check(
            "CZL-003",
            "Cloud identity can rewrite safety or speed parameters",
            "high",
            "Parameter writes reach the velocity smoother, controller server, collision monitor, or MoveIt, so "
            "speed caps and protective zones can be raised or switched off remotely.",
            "Bridge an explicit allowlist of tunable parameters, never '*'. Keep safety limits in a read-only "
            "parameter file and enforce the hard limit in the motor drives or safety PLC.",
            ("T0836",),
        ),
        Check(
            "CZL-004",
            "Cloud identity can send raw arm trajectories",
            "high",
            "FollowJointTrajectory goals go straight to the joint trajectory controller, skipping MoveIt "
            "collision checking and velocity scaling. The arm can move at its joint velocity limits.",
            "Expose only planned motion (MoveGroup) through the bridge, with a low velocity scaling factor, "
            "and require human approval for arm motion near people.",
            ("T0831", "T0855"),
        ),
        Check(
            "CZL-005",
            "Cloud identity can run code on the robots",
            "critical",
            "A Greengrass deployment or an IoT job with a command handler runs arbitrary software on the robot, "
            "which can drive every actuator at hardware limits and ignore every ROS-level safety layer.",
            "Limit greengrass:CreateDeployment and iot:CreateJob to the release pipeline, require signed "
            "components, and gate fleet-wide deployments behind a human approval step.",
            ("T0843", "T1648"),
        ),
        Check(
            "CZL-006",
            "AI agent reads untrusted input and can move robots without approval",
            "high",
            "The agent ingests content an outsider can write (tickets, camera scene text) and holds tools that "
            "move robots, with no human in the loop. Indirect prompt injection turns that text into motion.",
            "Turn on human approval for motion tools, strip raw-motion tools from the agent, and scope the tool "
            "role to goal-level commands on specific robots.",
            ("AML.T0051.001", "T0855"),
        ),
        Check(
            "CZL-007",
            "Identity can take over an AI agent or its tools",
            "high",
            "This identity can rewrite a tool's Lambda code or invoke the agent directly, so it inherits "
            "everything the tool's execution role can publish, not just what the tool was written to do.",
            "Remove lambda:UpdateFunctionCode from operator roles, scope tool roles to exact topics, and use "
            "Lambda code signing on agent tools.",
            ("T1648", "T1078.004"),
        ),
        Check(
            "CZL-008",
            "One identity can move most of the fleet",
            "medium",
            "Topic wildcards give a single identity command over most or all robots, so one compromise "
            "becomes a fleet-wide incident instead of a single-robot one.",
            "Scope iot:Publish to the robots a workload actually serves, for example by site or thing group, "
            "using IoT policy variables or per-site roles.",
            ("T1078.004",),
        ),
        Check(
            "CZL-009",
            "Robot network accepts unauthenticated ROS commands",
            "high",
            "ROS 2 security (SROS2) is off and a rosbridge endpoint listens without auth, so anything on the "
            "warehouse network can publish to any topic, cloud policies or not.",
            "Enable SROS2 with Enforce strategy and per-enclave permissions, and bind rosbridge to localhost "
            "or put it behind authentication.",
            ("T0855", "T0886"),
        ),
        Check(
            "CZL-010",
            "Worst-case impact exceeds human pain thresholds",
            "high",
            "At the fastest speed this identity can make the robot reach a person, the transferred energy is "
            "above the ISO/TS 15066 transient-contact limit for one or more body regions.",
            "Cap speed in shared zones at the safe speed Caziel reports, keep a collision monitor on every "
            "velocity path, and enforce the cap below ROS (drives or safety PLC).",
            ("T0880", "T0879"),
        ),
    )
}


def severity_at_least(sev: str, floor: str) -> bool:
    return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[floor]
