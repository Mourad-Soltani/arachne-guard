"""Agent identity: Ed25519-signed agent cards and a pinned-key trust store.

A card that merely *contains* a signature proves nothing. ``verify_card``
checks the signature cryptographically over the canonical JSON of every field
except the signature, and ``TrustStore`` pins which public key is allowed to
speak for which agent id, so a self-consistent forged card is still rejected.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from typing import Any, Dict, FrozenSet, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .capability import validate_pattern


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for signing and hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64(raw)


@dataclass(frozen=True)
class AgentCard:
    agent_id: str
    name: str
    version: str
    description: str = ""
    capabilities: FrozenSet[str] = frozenset()
    endpoint: Optional[str] = None
    public_key: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.agent_id or not self.agent_id.strip():
            raise ValueError("agent_id must not be blank")
        for cap in self.capabilities:
            validate_pattern(cap)

    def signing_payload(self) -> bytes:
        body = {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": sorted(self.capabilities),
            "endpoint": self.endpoint,
            "public_key": self.public_key,
            "metadata": dict(sorted(self.metadata.items())),
        }
        return canonical(body)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": sorted(self.capabilities),
            "endpoint": self.endpoint,
            "public_key": self.public_key,
            "signature": self.signature,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCard":
        return cls(
            agent_id=data["agent_id"],
            name=data["name"],
            version=data["version"],
            description=data.get("description", ""),
            capabilities=frozenset(data.get("capabilities", [])),
            endpoint=data.get("endpoint"),
            public_key=data.get("public_key"),
            signature=data.get("signature"),
            metadata=dict(data.get("metadata", {})),
        )


def sign_card(card: AgentCard, private_key: Ed25519PrivateKey) -> AgentCard:
    """Return a copy of ``card`` carrying the signer's public key and signature."""
    with_key = replace(card, public_key=public_key_b64(private_key), signature=None)
    sig = private_key.sign(with_key.signing_payload())
    return replace(with_key, signature=_b64(sig))


def verify_card(card: AgentCard) -> bool:
    """True only if the card's signature is valid for its embedded public key."""
    if not card.signature or not card.public_key:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64(card.public_key))
        key.verify(_unb64(card.signature), card.signing_payload())
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def rotation_payload(agent_id: str, new_public_key: str, counter: int) -> bytes:
    return canonical({"agent_id": agent_id, "new_public_key": new_public_key, "counter": counter})


def sign_rotation(old_private_key: Ed25519PrivateKey, agent_id: str, new_public_key: str, counter: int) -> str:
    """Statement, signed by the *old* key, authorizing a move to ``new_public_key``."""
    return _b64(old_private_key.sign(rotation_payload(agent_id, new_public_key, counter)))


class TrustStore:
    """Pins the public key allowed to speak for each agent id.

    - ``rotate`` needs a statement signed by the currently pinned key, with a
      strictly increasing counter so old statements cannot be replayed.
    - ``revoke`` is permanent: a revoked agent id can never be pinned again.
    - With ``path`` set, state is persisted atomically (mode 0600) and a
      corrupt file raises instead of silently starting empty.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._pins: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}
        self._revoked: set = set()
        self._path = path
        if path and os.path.exists(path):
            self._load(path)

    def pin(self, agent_id: str, public_key_b64_value: str) -> None:
        if agent_id in self._revoked:
            raise ValueError(f"agent {agent_id!r} is revoked")
        existing = self._pins.get(agent_id)
        if existing is not None and existing != public_key_b64_value:
            raise ValueError(f"agent {agent_id!r} is already pinned to a different key")
        self._pins[agent_id] = public_key_b64_value
        self._counters.setdefault(agent_id, 0)
        self._save()

    def rotate(self, agent_id: str, new_public_key: str, counter: int, signature: str) -> None:
        old = self._pins.get(agent_id)
        if old is None or agent_id in self._revoked:
            raise ValueError(f"agent {agent_id!r} is not pinned")
        if counter <= self._counters.get(agent_id, 0):
            raise ValueError("rotation counter must increase (possible replay)")
        try:
            Ed25519PublicKey.from_public_bytes(_unb64(new_public_key))  # must be a real key
            Ed25519PublicKey.from_public_bytes(_unb64(old)).verify(
                _unb64(signature), rotation_payload(agent_id, new_public_key, counter))
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise ValueError("rotation statement is not validly signed by the current key") from exc
        self._pins[agent_id] = new_public_key
        self._counters[agent_id] = counter
        self._save()

    def revoke(self, agent_id: str) -> bool:
        existed = self._pins.pop(agent_id, None) is not None
        self._revoked.add(agent_id)
        self._save()
        return existed

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked

    def is_pinned(self, card: AgentCard) -> bool:
        if card.agent_id in self._revoked:
            return False
        pinned = self._pins.get(card.agent_id)
        return pinned is not None and pinned == card.public_key

    def _save(self) -> None:
        if not self._path:
            return
        data = {"pins": self._pins, "counters": self._counters, "revoked": sorted(self._revoked)}
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trust-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _load(self, path: str) -> None:
        try:
            with open(path) as fh:
                data = json.load(fh)
            pins, counters, revoked = data["pins"], data["counters"], data["revoked"]
            if not (isinstance(pins, dict) and isinstance(counters, dict) and isinstance(revoked, list)):
                raise TypeError("wrong shape")
            for key in pins.values():
                Ed25519PublicKey.from_public_bytes(_unb64(key))
            self._pins, self._counters, self._revoked = dict(pins), dict(counters), set(revoked)
        except (OSError, ValueError, KeyError, TypeError, binascii.Error) as exc:
            raise ValueError(f"trust store at {path} is corrupt: {exc}") from exc
