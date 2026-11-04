# Contributing

Thanks for looking. Issues and PRs are welcome, especially:

- real-world robot stacks that Caziel misreads (a graph snapshot with secrets removed is the most useful thing you can send)
- more bridge styles (Greengrass ROS bridge variants, Zenoh, custom WebSocket bridges)
- IoT Core policy evaluation and IAM permission boundaries

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check . && mypy caziel
```

For the website check you also need Node 20:

```bash
npm ci && npx playwright install chromium
npm test
```

## Generated files

Three things are generated and checked in CI. If you change the engine, regenerate them:

```bash
python scripts/gen_checks_doc.py      # CHECKS.md from caziel/rules.py
python scripts/gen_traffic.py         # examples/harbor-fleet/traffic/shift.jsonl (seeded)
python scripts/build_site_data.py     # examples/harbor-fleet-hardened and docs/data/*
```

## Adding a check

1. Add a `Check` to `caziel/rules.py` with a plain-English `why` and `fix`, and framework IDs you can defend.
2. Emit it from `analysis._findings` (or `_network_findings` for robot-level issues).
3. Add a test that proves it fires on the example fleet *and* a test that proves it doesn't fire when the risk is fixed.
4. Regenerate the files above.

Keep the tone of findings factual. Caziel estimates physical risk to rank security work. It should never read like a safety certification.
