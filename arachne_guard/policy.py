"""Policy engine: allow / deny / ask over (agent, capability) with glob patterns.

Evaluation is fail-closed: any matching DENY wins, then any matching ASK, then
ALLOW; if no rule matches, the policy's default effect applies (DENY).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional

from .capability import matches, validate_pattern


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass(frozen=True)
class Rule:
    effect: Effect
    capability: str
    agent: str = "*"
    reason: str = ""

    def __post_init__(self) -> None:
        validate_pattern(self.capability)
        validate_pattern(self.agent)

    def applies(self, agent_id: str, capability: str) -> bool:
        return matches(self.agent, agent_id) and matches(self.capability, capability)


class Policy:
    def __init__(self, rules: Optional[Iterable[Rule]] = None, default: Effect = Effect.DENY):
        self._rules: List[Rule] = list(rules or [])
        self.default = default

    def add(self, rule: Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    def evaluate(self, agent_id: str, capability: str) -> "tuple[Effect, str]":
        hits = [r for r in self._rules if r.applies(agent_id, capability)]
        for effect in (Effect.DENY, Effect.ASK, Effect.ALLOW):
            for r in hits:
                if r.effect is effect:
                    return effect, r.reason or f"rule {effect.value} {r.agent}/{r.capability}"
        return self.default, f"no rule matched; default {self.default.value}"


def policy_from_dict(data: dict) -> Policy:
    """Build a Policy from ``{"default": "deny", "rules": [{effect, capability, agent?, reason?}]}``."""
    default = Effect(data.get("default", "deny"))
    rules = []
    for i, raw in enumerate(data.get("rules", [])):
        try:
            rules.append(Rule(
                effect=Effect(raw["effect"]),
                capability=raw["capability"],
                agent=raw.get("agent", "*"),
                reason=raw.get("reason", ""),
            ))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid rule at index {i}: {exc}") from exc
    return Policy(rules, default)


def load_policy(path: str) -> Policy:
    import json
    with open(path) as fh:
        return policy_from_dict(json.load(fh))
