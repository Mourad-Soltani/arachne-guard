"""Signed requests: proof that the caller holds the agent's private key.

A public agent card alone must not let anyone act as the agent. The agent signs
the canonical form of (agent id, jsonrpc, id, method, params, nonce, ts) and
attaches it as ``auth``. Verification uses the key embedded in the card, which
the gateway separately requires to be pinned.
"""
from __future__ import annotations

import binascii
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .identity import AgentCard, _b64, _unb64, canonical


def _payload(agent_id: str, request: Dict[str, Any], nonce: str, ts: float) -> bytes:
    return canonical({
        "agent_id": agent_id,
        "jsonrpc": request.get("jsonrpc"),
        "id": request.get("id"),
        "method": request.get("method"),
        "params": request.get("params"),
        "nonce": nonce,
        "ts": ts,
    })


def sign_request(private_key: Ed25519PrivateKey, agent_id: str, request: Dict[str, Any],
                 nonce: Optional[str] = None, ts: Optional[float] = None) -> Dict[str, Any]:
    nonce = nonce or secrets.token_hex(16)
    ts = time.time() if ts is None else ts
    sig = _b64(private_key.sign(_payload(agent_id, request, nonce, ts)))
    return dict(request, auth={"nonce": nonce, "ts": ts, "sig": sig})


def verify_request(card: AgentCard, request: Dict[str, Any]) -> Tuple[bool, str]:
    auth = request.get("auth")
    if not isinstance(auth, dict) or not card.public_key:
        return False, "missing auth"
    nonce, ts, sig = auth.get("nonce"), auth.get("ts"), auth.get("sig")
    if not isinstance(nonce, str) or isinstance(ts, bool) or not isinstance(ts, (int, float)) \
            or not isinstance(sig, str):
        return False, "malformed auth"
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(card.public_key)).verify(
            _unb64(sig), _payload(card.agent_id, request, nonce, ts))
        return True, "ok"
    except (InvalidSignature, ValueError, binascii.Error):
        return False, "bad request signature"
