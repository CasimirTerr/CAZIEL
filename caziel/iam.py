"""A small, offline IAM policy evaluator.

It covers what Caziel needs to answer "can this identity publish to this MQTT topic
or deploy code to this robot": Allow/Deny statements, Action/NotAction, Resource/NotResource,
and wildcards. Explicit Deny always wins. Conditions are not evaluated; a statement with a
Condition block is treated as applying (the conservative choice for a blast-radius tool),
and the result is flagged so the report can say so.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


@lru_cache(maxsize=4096)
def _compile(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    # IAM wildcards: '*' matches any run of characters, '?' matches one character.
    regex = fnmatch.translate(pattern)
    return re.compile(regex, re.IGNORECASE if case_insensitive else 0)


def action_matches(pattern: str, action: str) -> bool:
    """Action names are case-insensitive in IAM."""
    return bool(_compile(pattern, True).match(action))


def resource_matches(pattern: str, resource: str) -> bool:
    """ARNs are case-sensitive."""
    return bool(_compile(pattern, False).match(resource))


@dataclass
class Statement:
    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    has_condition: bool = False
    sid: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Statement:
        effect = str(raw.get("Effect", "")).capitalize()
        if effect not in ("Allow", "Deny"):
            raise ValueError(f"statement {raw.get('Sid', '?')!r} has invalid Effect {raw.get('Effect')!r}")
        return cls(
            effect=effect,
            actions=_as_list(raw.get("Action")),
            not_actions=_as_list(raw.get("NotAction")),
            resources=_as_list(raw.get("Resource")),
            not_resources=_as_list(raw.get("NotResource")),
            has_condition=bool(raw.get("Condition")),
            sid=str(raw.get("Sid", "")),
        )

    def covers_action(self, action: str) -> bool:
        if self.actions:
            return any(action_matches(p, action) for p in self.actions)
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return False

    def covers_resource(self, resource: str) -> bool:
        if self.resources:
            return any(resource_matches(p, resource) for p in self.resources)
        if self.not_resources:
            return not any(resource_matches(p, resource) for p in self.not_resources)
        return False

    def applies(self, action: str, resource: str) -> bool:
        return self.covers_action(action) and self.covers_resource(resource)


@dataclass
class Decision:
    allowed: bool
    matched: list[str] = field(default_factory=list)
    conditional: bool = False


class PolicySet:
    """All identity policies attached to one principal."""

    def __init__(self, documents: list[dict[str, Any]]):
        self.statements: list[Statement] = []
        for doc in documents:
            raw = doc.get("Statement", [])
            if isinstance(raw, dict):
                raw = [raw]
            self.statements.extend(Statement.from_dict(s) for s in raw)

    def evaluate(self, action: str, resource: str) -> Decision:
        allows = [s for s in self.statements if s.effect == "Allow" and s.applies(action, resource)]
        denies = [s for s in self.statements if s.effect == "Deny" and s.applies(action, resource)]
        # An unconditional explicit Deny wins outright. A conditional Deny may or may not fire,
        # so a blast-radius tool must assume it might not.
        if any(not s.has_condition for s in denies):
            return Decision(False, [s.sid or "Deny" for s in denies])
        if allows:
            return Decision(
                True,
                [s.sid or "Allow" for s in allows],
                conditional=all(s.has_condition for s in allows) or bool(denies),
            )
        return Decision(False)

    def allows(self, action: str, resource: str) -> bool:
        return self.evaluate(action, resource).allowed
