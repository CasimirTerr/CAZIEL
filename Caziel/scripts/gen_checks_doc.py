"""Regenerate CHECKS.md from caziel/rules.py so the docs never drift from the code.

python scripts/gen_checks_doc.py           # write CHECKS.md
python scripts/gen_checks_doc.py --check   # exit 1 if CHECKS.md is stale (used in CI)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from caziel import rules  # noqa: E402

LINKS = {
    "T08": "https://attack.mitre.org/techniques/{id}/",
    "T1": "https://attack.mitre.org/techniques/{path}/",
    "AML": "https://atlas.mitre.org/techniques/{id}",
}


def link(tid: str) -> str:
    if tid.startswith("AML"):
        return f"[{tid}](https://atlas.mitre.org/techniques/{tid})"
    path = tid.replace(".", "/")
    return f"[{tid}](https://attack.mitre.org/techniques/{path}/)"


def render() -> str:
    out = [
        "# Checks",
        "",
        "Generated from `caziel/rules.py` by `scripts/gen_checks_doc.py`. Do not edit by hand.",
        "",
        "IDs starting with `T08` are MITRE ATT&CK for ICS, `T1` are ATT&CK Enterprise, and `AML` are MITRE ATLAS.",
        "",
        "| ID | Severity | Check |",
        "|---|---|---|",
    ]
    out += [f"| [{c.id}](#{c.id.lower()}) | {c.severity} | {c.title} |" for c in rules.CHECKS.values()]
    for c in rules.CHECKS.values():
        out += [
            "",
            f"## {c.id}",
            "",
            f"**{c.title}** · {c.severity}",
            "",
            c.why,
            "",
            f"**Fix.** {c.fix}",
            "",
            "**Maps to:** " + ", ".join(link(t) for t in c.attack),
        ]
    return "\n".join(out) + "\n"


def main() -> int:
    target = ROOT / "CHECKS.md"
    text = render()
    if "--check" in sys.argv:
        if not target.exists() or target.read_text() != text:
            print("CHECKS.md is out of date. Run: python scripts/gen_checks_doc.py", file=sys.stderr)
            return 1
        return 0
    target.write_text(text)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
