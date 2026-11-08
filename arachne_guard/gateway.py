"""Gateway: the single choke point every agent action passes through."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .audit import AuditLog
from .capability import matches, validate_capability
from .consent import ConsentGate
from .identity import AgentCard, TrustStore, verify_card
from .policy import Effect, Policy


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class PermissionDenied(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


class Gateway:
    def __init__(
        self,
        trust: TrustStore,
        policy: Policy,
        consent: Optional[ConsentGate] = None,
        audit: Optional[AuditLog] = None,
    ):
        self.trust = trust
        self.policy = policy
        self.consent = consent or ConsentGate()
        self.audit = audit or AuditLog()

    def authorize(self, card: AgentCard, capability: str) -> Decision:
        decision = self._decide(card, capability)
        self.audit.append(
            "authorize",
            {"agent": card.agent_id, "capability": capability,
             "allowed": decision.allowed, "reason": decision.reason},
        )
        return decision

    def _decide(self, card: AgentCard, capability: str) -> Decision:
        try:
            validate_capability(capability)
        except ValueError as exc:
            return Decision(False, f"invalid capability: {exc}")
        if not verify_card(card):
            return Decision(False, "card signature invalid or missing")
        if not self.trust.is_pinned(card):
            return Decision(False, "agent key not pinned in trust store")
        if not any(matches(declared, capability) for declared in card.capabilities):
            return Decision(False, "capability not declared on agent card")
        effect, why = self.policy.evaluate(card.agent_id, capability)
        if effect is Effect.DENY:
            return Decision(False, f"policy denied: {why}")
        if effect is Effect.ASK:
            ok, note = self.consent.request(card.agent_id, capability)
            return Decision(ok, f"consent: {note}")
        return Decision(True, f"policy allowed: {why}")

    def invoke(self, card: AgentCard, capability: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run ``fn`` only if authorized; audit the outcome either way."""
        decision = self.authorize(card, capability)
        if not decision.allowed:
            raise PermissionDenied(decision)
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            self.audit.append("invoke_error", {"agent": card.agent_id, "capability": capability, "error": repr(exc)})
            raise
        self.audit.append("invoke_ok", {"agent": card.agent_id, "capability": capability})
        return result
