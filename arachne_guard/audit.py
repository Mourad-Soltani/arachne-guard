"""Tamper-evident audit log: each entry hashes the previous entry's hash."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .identity import _b64, _unb64, canonical

GENESIS = "0" * 64


def _entry_hash(prev_hash: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical(body)).hexdigest()


class AuditLog:
    def __init__(self, path: Optional[str] = None, clock: Callable[[], float] = time.time):
        self._entries: List[Dict[str, Any]] = []
        self._clock = clock
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            for line in self._path.read_text().splitlines():
                if line.strip():
                    self._entries.append(json.loads(line))
            ok, bad = self.verify()
            if not ok:
                raise ValueError(f"audit log at {self._path} failed verification at entry {bad}")

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    @property
    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def append(self, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
        body = {"seq": len(self._entries), "ts": self._clock(), "event": event, "data": data}
        entry = dict(body, prev_hash=self.head)
        entry["hash"] = _entry_hash(entry["prev_hash"], body)
        self._entries.append(entry)
        if self._path:
            with self._path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return dict(entry)

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Return (True, None) if intact, else (False, index of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(self._entries):
            body = {k: e.get(k) for k in ("seq", "ts", "event", "data")}
            if e.get("seq") != i or e.get("prev_hash") != prev:
                return False, i
            if e.get("hash") != _entry_hash(prev, body):
                return False, i
            prev = e["hash"]
        return True, None

    def checkpoint(self, private_key: Any) -> Dict[str, Any]:
        """Signed (count, head) snapshot. Store it OUTSIDE the log's trust domain."""
        body = {"count": len(self._entries), "head": self.head, "ts": self._clock()}
        return dict(body, signature=_b64(private_key.sign(canonical(body))))

    def verify_checkpoint(self, checkpoint: Dict[str, Any], public_key_b64: str) -> Tuple[bool, str]:
        """Detects truncation and whole-log rewrites after the checkpoint was taken."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import binascii
        try:
            body = {k: checkpoint[k] for k in ("count", "head", "ts")}
            Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64)).verify(
                _unb64(checkpoint["signature"]), canonical(body))
        except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
            return False, "checkpoint signature invalid"
        ok, bad = self.verify()
        if not ok:
            return False, f"chain broken at entry {bad}"
        count = body["count"]
        if not isinstance(count, int) or count < 0 or count > len(self._entries):
            return False, "log is shorter than checkpoint (truncated)"
        expected = GENESIS if count == 0 else self._entries[count - 1]["hash"]
        if body["head"] != expected:
            return False, "log history differs from checkpoint (rewritten)"
        return True, "ok"

