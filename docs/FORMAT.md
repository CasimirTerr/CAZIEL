# Fleet directory format

Caziel reads a directory of plain files, so you can build one from exports you already have and check it into a repo.

```
my-fleet/
├── fleet.yaml
├── cloud/
│   ├── iam.json
│   └── agents.yaml
└── robots/
    └── <model>/
        ├── robot.yaml
        ├── robot.urdf
        ├── params.yaml
        ├── graph.json
        └── bridge.yaml
```

## fleet.yaml

```yaml
name: Harbor Logistics - Tempe DC
account_id: "111122223333"
region: us-west-2

robots:
  - model: kx1                 # directory under robots/
    thing_group: kx1-fleet     # used for Greengrass / Jobs targets
    things: {prefix: kx1-, count: 12}   # or an explicit list: [kx1-01, kx1-02]

iot:
  jobs:
    enabled: true
    handler: shell             # "shell" = job documents can run commands (counts as code execution)
  greengrass:
    enabled: true              # greengrass:CreateDeployment counts as code execution

site:
  people_present: true
  body_regions: [hand, forearm, upper_arm, chest, abdomen, thigh]
  body_region_overrides:       # optional, if your safety team uses different values
    chest: {force_n: 280, k_n_per_m: 25000, mass_kg: 40}

identities: cloud/iam.json
agents: cloud/agents.yaml

accepted_risks:                # optional; accepted findings are reported but not counted or failed on
  - actor: principal:release-pipeline-role
    checks: [CZL-005]          # or check: CZL-005, or "*"
    reason: Release pipeline has to deploy. Components are signed.
```

## cloud/iam.json

Export each principal's identity policies (managed and inline) as policy documents.

```json
{
  "principals": [
    {
      "name": "ops-console-role",
      "kind": "role",
      "arn": "arn:aws:iam::111122223333:role/ops-console-role",
      "unique_id": "AROA4HRBROPSCONSOLE",
      "purpose": "Fleet operations web console",
      "exposure": "Cognito-federated sessions in operators' browsers",
      "tags": {"caziel:role": "release"},
      "policies": [ { "Version": "2012-10-17", "Statement": [ ... ] } ]
    }
  ]
}
```

`unique_id` is the principal's AROA/AIDA ID. AWS IoT Core reports IAM callers by that ID, so `caziel watch` needs it to say who sent a command. `exposure` is free text shown as the entry point ("Stolen credentials (...)"). The tag `caziel:role: release` marks a deploy pipeline. `caziel fix` accepts its code-deploy finding with a condition instead of blocking it.

A quick way to build this file is `aws iam get-account-authorization-details`, then reshape it with `jq`.

## cloud/agents.yaml

```yaml
agents:
  - name: dispatch-agent
    runtime: bedrock-agentcore          # or bedrock-agent
    arn: arn:aws:bedrock-agentcore:us-west-2:111122223333:runtime/dispatch_agent-Qm7tR2xK9p
    role: dispatch-agent-role
    human_approval: false               # true gates every motion this agent can cause
    untrusted_inputs:                   # anything an outsider can write that the model reads
      - Work-order tickets from the customer portal
    tools:
      - name: nudge
        function: arn:aws:lambda:us-west-2:111122223333:function:fleet-nudge
        role: fleet-tools-role          # the Lambda's execution role (must exist in iam.json)
        publishes: fleet/{thing}/cmd/velocity   # must match a bridge mapping
```

An identity with `bedrock-agentcore:InvokeAgentRuntime` (or `bedrock:InvokeAgent`) on the agent inherits the agent's reach. An identity with `lambda:UpdateFunctionCode` on a tool's function inherits the tool *role's* reach, not just what the tool was written to do.

## robots/&lt;model&gt;/robot.yaml

```yaml
model: KX-1 mobile manipulator
urdf: robot.urdf
params: params.yaml
graph: graph.json
bridge: bridge.yaml
payload_kg: 4.0
base:
  controller: /diff_drive_controller   # node that drives the wheels
  hardware_max_speed_mps: 2.2           # used if the controller has no velocity limit
arm:                                    # optional
  urdf_root: arm_mount
  urdf_tip: gripper_tcp
  controller: /arm_controller
```

## params.yaml and graph.json

`params.yaml` is a normal ROS 2 parameter file (`ros2 param dump` output for each node, merged together). `graph.json` comes from `caziel snapshot`:

```json
{
  "environment": {"ROS_DOMAIN_ID": "7", "ROS_SECURITY_ENABLE": "false"},
  "nodes": [
    {"name": "/collision_monitor",
     "publishers":  [{"name": "/cmd_vel", "type": "geometry_msgs/msg/Twist"}],
     "subscribers": [{"name": "/cmd_vel_smoothed", "type": "geometry_msgs/msg/Twist"}],
     "services": [{"name": "/collision_monitor/change_state", "type": "lifecycle_msgs/srv/ChangeState"}],
     "action_servers": []}
  ]
}
```

Caziel recognises nodes by their parameters, not their names:

| Role | Recognised by |
|---|---|
| collision monitor | `cmd_vel_in_topic` plus `observation_sources` or `polygons` |
| velocity smoother | `max_velocity` plus `smoothing_frequency` or `feedback` |
| controller server | `controller_plugins` or any `*.max_vel_x` |
| MoveIt | `default_velocity_scaling_factor` |

## bridge.yaml

```yaml
name: kx1-edge-bridge
runtime: greengrass-component
mappings:
  - mqtt: fleet/{thing}/cmd/navigate
    ros: {kind: action, name: /navigate_to_pose, type: nav2_msgs/action/NavigateToPose}
  - mqtt: fleet/{thing}/cmd/velocity
    requires_approval: true
    ros: {kind: topic, name: /cmd_vel_smoothed, type: geometry_msgs/msg/Twist}
  - mqtt: fleet/{thing}/cmd/param
    ros: {kind: parameters, nodes: ["*"]}       # or a list of nodes
  - mqtt: fleet/{thing}/cmd/lifecycle
    ros: {kind: lifecycle, nodes: [/bt_navigator]}
ros_security: {enabled: false}
lan: {endpoint: 0.0.0.0:9090, auth: none}       # on-robot rosbridge, if any
```

`kind` is one of `topic`, `action`, `parameters`, `lifecycle`, `service`.

## Live traffic for `caziel watch`

One JSON object per line, as an AWS IoT rule writes it:

```sql
SELECT topic() AS topic, principal() AS principal, clientid() AS client_id,
       timestamp() AS ts, * AS payload
FROM 'fleet/+/cmd/#'
```

```json
{"ts": 1762207296000, "topic": "fleet/kx1-07/cmd/velocity", "principal": "AROA4HRBRFLEETTOOLS:fleet-nudge",
 "client_id": "fleet-tools-nudge", "payload": {"linear": {"x": 1.9}, "duration_s": 4.0}}
```

The payload is used where it matters:

- `linear.x` on velocity topics: the asked-for speed
- `node`, `name` and `value` on parameter writes
- `node` and `transition` on lifecycle commands

A session name that matches an agent tool's Lambda function name is reported as that tool.
