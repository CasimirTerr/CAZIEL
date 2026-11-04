# Changelog

## 1.0.0 (2026-11-04)

First public release.

- `caziel scan`: cloud-to-physical reach for every IAM principal and every AI agent (as if prompt-injected), with text, Markdown and JSON output and `--fail-on`.
- Offline IAM evaluator (Allow/Deny, NotAction/NotResource, wildcards, conservative handling of conditions).
- Escalation edges: invoking an agent, and rewriting an agent tool's Lambda code.
- Code-execution paths through IoT Jobs (shell handlers) and Greengrass deployments.
- ROS 2 velocity dataflow analysis: finds commands that reach the base without passing the collision monitor, and parameter or lifecycle access that lifts caps or shuts safety nodes down.
- URDF arm envelope: reach, moving mass, worst-case tool-tip speed bound.
- ISO/TS 15066-style transient-contact energy model with per-fleet overrides.
- `caziel fix`: hardened fleet copy that rescans clean, `CHANGES.md`, SROS2 permissions, an Organizations SCP, and accepted-risk entries with written conditions.
- `caziel watch`: live classification of AWS IoT Core command traffic (JSON lines from an IoT rule), with attribution of Lambda sessions to agent tools, per-robot state for lifted limits, and checks against the current IAM policies.
- `caziel snapshot` for capturing `graph.json` and parameters from a live robot.
- 10 checks mapped to MITRE ATT&CK for ICS, ATT&CK Enterprise and MITRE ATLAS.
- Website: a live 3D view of a recorded shift classified by `caziel watch`, replays of each attack chain before and after the fix, and an "Ask Claude" panel with tools to move the camera and pull alerts. Everything on it comes from the engine's own output.
