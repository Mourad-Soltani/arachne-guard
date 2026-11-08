"""Heuristic scan of tool output for secrets and prompt-injection phrasing.

These are pattern heuristics, not a guarantee: they catch common, careless
cases and give a policy hook. A determined attacker can evade them.
"""
from __future__ import annotations

import re
from typing import Any, List, Tuple

SECRETS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "credential_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/]{12,}"),
}
INJECTION = {
    "override_instructions": re.compile(
        r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b"
        r"[^.\n]{0,40}\binstructions?\b"),
    "reveal_prompt": re.compile(
        r"(?i)\b(?:reveal|print|show|output)\b[^.\n]{0,30}\b(?:system prompt|hidden instructions)\b"),
    "exfiltrate_to_url": re.compile(r"(?i)\bsend\b[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,20}https?://"),
}
MAX_DEPTH = 20


class OutputBlocked(Exception):
    def __init__(self, kinds: List[str]):
        super().__init__("output blocked: " + ", ".join(kinds))
        self.kinds = kinds


class OutputInspector:
    def __init__(self, on_secret: str = "redact", on_injection: str = "flag"):
        if on_secret not in ("redact", "block", "flag") or on_injection not in ("flag", "block"):
            raise ValueError("on_secret in redact|block|flag; on_injection in flag|block")
        self.on_secret, self.on_injection = on_secret, on_injection

    def apply(self, obj: Any) -> Tuple[Any, List[str]]:
        """Return (possibly redacted object, sorted finding kinds). Raises OutputBlocked."""
        kinds: set = set()
        clean = self._walk(obj, kinds, 0)
        found = sorted(kinds)
        secret_hit = [k for k in found if k in SECRETS]
        inj_hit = [k for k in found if k in INJECTION]
        if (secret_hit and self.on_secret == "block") or (inj_hit and self.on_injection == "block"):
            raise OutputBlocked(found)
        return clean, found

    def _walk(self, obj: Any, kinds: set, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise OutputBlocked(["too_deep"])
        if isinstance(obj, str):
            return self._text(obj, kinds)
        if isinstance(obj, (list, tuple)):
            return [self._walk(x, kinds, depth + 1) for x in obj]
        if isinstance(obj, dict):
            return {k: self._walk(v, kinds, depth + 1) for k, v in obj.items()}
        return obj

    def _text(self, text: str, kinds: set) -> str:
        for kind, rx in INJECTION.items():
            if rx.search(text):
                kinds.add(kind)
        for kind, rx in SECRETS.items():
            if rx.search(text):
                kinds.add(kind)
                if self.on_secret == "redact":
                    text = rx.sub(f"[REDACTED:{kind}]", text)
        return text
