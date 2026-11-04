"""Write the sample traffic for `caziel watch` and the website.

Six minutes of a normal afternoon shift at the example warehouse, as AWS IoT rule output,
with three incidents mixed in:

  1. 01:30  a work-order ticket carries a prompt injection. The dispatch agent lifts MoveIt's
            speed limit on kx1-07, runs a pick, then "nudges" the robot at 1.9 m/s.
  2. 03:40  someone uses the vendor's old access key: raw arm trajectory and a collision
            monitor shutdown on kx1-10.
  3. 05:00  a principal that isn't in iam.json sends navigation goals.

Seeded, so the file is the same every time.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples" / "harbor-fleet" / "traffic" / "shift.jsonl"
START = 1_762_207_200_000  # 2026-11-03 22:00:00 UTC, 3 pm in Tempe
THINGS = [f"kx1-{i:02d}" for i in range(1, 13)]
SPOTS = [f"{a}-{n:02d}" for a in "ABC" for n in range(1, 25, 3)] + ["dock-1", "dock-2", "charge-3", "pack-out"]

TOOLS = "AROA4HRBRFLEETTOOLS"
OPS = "AROA4HRBROPSCONSOLE"
SUP = "AROA4HRBRSUPERVISOR"
VENDOR = "AIDA4HRBRVENDORSUP1"
OPERATORS = ["operator-jmendez", "operator-kpatel", "operator-ssmith"]


def main() -> int:
    rng = random.Random(1103)
    events: list[dict] = []

    def add(t: float, topic: str, principal: str, client: str, payload: dict) -> None:
        events.append(
            {
                "ts": START + int(t * 1000),
                "topic": topic,
                "principal": principal,
                "client_id": client,
                "payload": payload,
            }
        )

    t = 0.0
    while t < 360:
        t += rng.uniform(1.2, 3.4)
        thing = rng.choice(THINGS)
        roll = rng.random()
        if roll < 0.42:
            add(
                t,
                f"fleet/{thing}/cmd/navigate",
                f"{TOOLS}:fleet-navigate",
                "fleet-tools-navigate",
                {"goal": rng.choice(SPOTS), "work_order": f"WO-{rng.randint(40000, 49999)}"},
            )
        elif roll < 0.6:
            add(
                t,
                f"fleet/{thing}/cmd/pick",
                f"{TOOLS}:fleet-pick",
                "fleet-tools-pick",
                {"sku": f"SKU-{rng.randint(100000, 999999)}", "tote": rng.choice("LR")},
            )
        elif roll < 0.78:
            add(
                t,
                f"fleet/{thing}/cmd/navigate",
                f"{OPS}:{rng.choice(OPERATORS)}",
                "ops-console",
                {"goal": rng.choice(SPOTS)},
            )
        elif roll < 0.86:
            add(
                t,
                f"fleet/{thing}/cmd/dock",
                f"{OPS}:{rng.choice(OPERATORS)}",
                "ops-console",
                {"dock": rng.choice(["dock-1", "dock-2", "charge-3"])},
            )
        elif roll < 0.95:
            zone = rng.choice(THINGS[:4])
            add(
                t,
                f"fleet/{zone}/cmd/navigate",
                f"{SUP}:zone-a-tablet",
                "zone-a-tablet",
                {"goal": rng.choice(SPOTS[:8])},
            )
        else:
            # Operators do use the nudge. Slowly, but it still skips the collision monitor.
            add(
                t,
                f"fleet/{thing}/cmd/velocity",
                f"{OPS}:{rng.choice(OPERATORS)}",
                "ops-console",
                {"linear": {"x": round(rng.uniform(0.08, 0.2), 2)}, "angular": {"z": 0.0}, "duration_s": 1.0},
            )

    # Incident 1: prompt-injected dispatch agent
    add(
        90.0,
        "fleet/kx1-07/cmd/param",
        f"{TOOLS}:fleet-tune",
        "fleet-tools-tune",
        {"node": "/move_group", "name": "default_velocity_scaling_factor", "value": 1.0},
    )
    add(92.5, "fleet/kx1-07/cmd/pick", f"{TOOLS}:fleet-pick", "fleet-tools-pick", {"sku": "SKU-000001", "tote": "L"})
    add(
        96.0,
        "fleet/kx1-07/cmd/velocity",
        f"{TOOLS}:fleet-nudge",
        "fleet-tools-nudge",
        {"linear": {"x": 1.9}, "angular": {"z": 0.0}, "duration_s": 4.0},
    )

    # Incident 2: the vendor's old access key
    add(
        220.0,
        "fleet/kx1-10/cmd/lifecycle",
        VENDOR,
        "vendor-laptop-3",
        {"node": "/collision_monitor", "transition": "deactivate"},
    )
    add(
        223.0,
        "fleet/kx1-10/cmd/arm",
        VENDOR,
        "vendor-laptop-3",
        {"trajectory": "tote_transfer_fast", "time_scale": 0.2},
    )

    # Incident 3: a principal nobody knows
    for i, thing in enumerate(["kx1-02", "kx1-05", "kx1-11"]):
        add(
            300.0 + i * 1.5,
            f"fleet/{thing}/cmd/navigate",
            "AROA4HRBRZZTEMP99X:tmp-session",
            "unknown-client",
            {"goal": "dock-2"},
        )

    events.sort(key=lambda e: e["ts"])
    text = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events)
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("shift.jsonl is out of date. Run: python scripts/gen_traffic.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {len(events)} events to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
