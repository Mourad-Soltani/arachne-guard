"""Human-in-the-loop consent gate. Fails closed on missing approver or errors."""
from __future__ import annotations

from typing import Callable, Optional

Approver = Callable[[str, str], bool]


class ConsentGate:
    def __init__(self, approver: Optional[Approver] = None):
        self._approver = approver

    def request(self, agent_id: str, capability: str) -> "tuple[bool, str]":
        if self._approver is None:
            return False, "no approver configured"
        try:
            approved = bool(self._approver(agent_id, capability))
        except Exception as exc:  # fail closed: an erroring approver never approves
            return False, f"approver error: {exc}"
        return approved, "user approved" if approved else "user denied"
