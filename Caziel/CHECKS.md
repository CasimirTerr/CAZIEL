# Checks

Generated from `caziel/rules.py` by `scripts/gen_checks_doc.py`. Do not edit by hand.

IDs starting with `T08` are MITRE ATT&CK for ICS, `T1` are ATT&CK Enterprise, and `AML` are MITRE ATLAS.

| ID | Severity | Check |
|---|---|---|
| [CZL-001](#czl-001) | critical | Cloud identity can drive the base around the collision monitor |
| [CZL-002](#czl-002) | high | Cloud identity can shut down a safety node |
| [CZL-003](#czl-003) | high | Cloud identity can rewrite safety or speed parameters |
| [CZL-004](#czl-004) | high | Cloud identity can send raw arm trajectories |
| [CZL-005](#czl-005) | critical | Cloud identity can run code on the robots |
| [CZL-006](#czl-006) | high | AI agent reads untrusted input and can move robots without approval |
| [CZL-007](#czl-007) | high | Identity can take over an AI agent or its tools |
| [CZL-008](#czl-008) | medium | One identity can move most of the fleet |
| [CZL-009](#czl-009) | high | Robot network accepts unauthenticated ROS commands |
| [CZL-010](#czl-010) | high | Worst-case impact exceeds human pain thresholds |

## CZL-001

**Cloud identity can drive the base around the collision monitor** · critical

Velocity commands from the cloud land on a topic downstream of the robot's collision monitor, so the node that is supposed to stop the robot before it hits someone never sees them.

**Fix.** Remove raw velocity from the edge bridge, or point it at the collision monitor's input topic. Deny iot:Publish on fleet/*/cmd/velocity for every role that does not need teleoperation.

**Maps to:** [T0855](https://attack.mitre.org/techniques/T0855/), [T0880](https://attack.mitre.org/techniques/T0880/)

## CZL-002

**Cloud identity can shut down a safety node** · high

Lifecycle transitions are exposed through the bridge, so a cloud message can deactivate the collision monitor. That halts navigation for the whole fleet and removes the safety layer.

**Fix.** Do not bridge lifecycle services. Use SROS2 to deny change_state on safety nodes to the bridge enclave.

**Maps to:** [T0813](https://attack.mitre.org/techniques/T0813/), [T0880](https://attack.mitre.org/techniques/T0880/)

## CZL-003

**Cloud identity can rewrite safety or speed parameters** · high

Parameter writes reach the velocity smoother, controller server, collision monitor, or MoveIt, so speed caps and protective zones can be raised or switched off remotely.

**Fix.** Bridge an explicit allowlist of tunable parameters, never '*'. Keep safety limits in a read-only parameter file and enforce the hard limit in the motor drives or safety PLC.

**Maps to:** [T0836](https://attack.mitre.org/techniques/T0836/)

## CZL-004

**Cloud identity can send raw arm trajectories** · high

FollowJointTrajectory goals go straight to the joint trajectory controller, skipping MoveIt collision checking and velocity scaling. The arm can move at its joint velocity limits.

**Fix.** Expose only planned motion (MoveGroup) through the bridge, with a low velocity scaling factor, and require human approval for arm motion near people.

**Maps to:** [T0831](https://attack.mitre.org/techniques/T0831/), [T0855](https://attack.mitre.org/techniques/T0855/)

## CZL-005

**Cloud identity can run code on the robots** · critical

A Greengrass deployment or an IoT job with a command handler runs arbitrary software on the robot, which can drive every actuator at hardware limits and ignore every ROS-level safety layer.

**Fix.** Limit greengrass:CreateDeployment and iot:CreateJob to the release pipeline, require signed components, and gate fleet-wide deployments behind a human approval step.

**Maps to:** [T0843](https://attack.mitre.org/techniques/T0843/), [T1648](https://attack.mitre.org/techniques/T1648/)

## CZL-006

**AI agent reads untrusted input and can move robots without approval** · high

The agent ingests content an outsider can write (tickets, camera scene text) and holds tools that move robots, with no human in the loop. Indirect prompt injection turns that text into motion.

**Fix.** Turn on human approval for motion tools, strip raw-motion tools from the agent, and scope the tool role to goal-level commands on specific robots.

**Maps to:** [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001), [T0855](https://attack.mitre.org/techniques/T0855/)

## CZL-007

**Identity can take over an AI agent or its tools** · high

This identity can rewrite a tool's Lambda code or invoke the agent directly, so it inherits everything the tool's execution role can publish, not just what the tool was written to do.

**Fix.** Remove lambda:UpdateFunctionCode from operator roles, scope tool roles to exact topics, and use Lambda code signing on agent tools.

**Maps to:** [T1648](https://attack.mitre.org/techniques/T1648/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/)

## CZL-008

**One identity can move most of the fleet** · medium

Topic wildcards give a single identity command over most or all robots, so one compromise becomes a fleet-wide incident instead of a single-robot one.

**Fix.** Scope iot:Publish to the robots a workload actually serves, for example by site or thing group, using IoT policy variables or per-site roles.

**Maps to:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/)

## CZL-009

**Robot network accepts unauthenticated ROS commands** · high

ROS 2 security (SROS2) is off and a rosbridge endpoint listens without auth, so anything on the warehouse network can publish to any topic, cloud policies or not.

**Fix.** Enable SROS2 with Enforce strategy and per-enclave permissions, and bind rosbridge to localhost or put it behind authentication.

**Maps to:** [T0855](https://attack.mitre.org/techniques/T0855/), [T0886](https://attack.mitre.org/techniques/T0886/)

## CZL-010

**Worst-case impact exceeds human pain thresholds** · high

At the fastest speed this identity can make the robot reach a person, the transferred energy is above the ISO/TS 15066 transient-contact limit for one or more body regions.

**Fix.** Cap speed in shared zones at the safe speed Caziel reports, keep a collision monitor on every velocity path, and enforce the cap below ROS (drives or safety PLC).

**Maps to:** [T0880](https://attack.mitre.org/techniques/T0880/), [T0879](https://attack.mitre.org/techniques/T0879/)
