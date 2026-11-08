"""MCP guard: a JSON-RPC 2.0 front for tools that enforces the Gateway.

Tool ``foo`` maps to capability ``mcp.call:foo``. ``tools/list`` shows an agent
only tools its policy does not outright deny. ``tools/call`` is authorized,
rate limited, argument-checked, and audited. Audit entries record argument
*names* only, never values, so secrets and personal data stay out of the log.
"""
from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .gateway import Gateway, PermissionDenied
from .identity import AgentCard
from .policy import Effect
from .outputscan import OutputBlocked, OutputInspector
from .ratelimit import RateLimiter
from .replay import ReplayGuard
from .request_auth import verify_request
from .identity import verify_card

_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL = (
    -32700, -32600, -32601, -32602, -32603)
PERMISSION_DENIED, RATE_LIMITED, AUTH_FAILED, REPLAYED, OUTPUT_BLOCKED = (
    -32001, -32002, -32003, -32004, -32005)


def tool_capability(name: str) -> str:
    return f"mcp.call:{name}"


@dataclass
class Tool:
    name: str
    description: str
    handler: Callable[..., Any]
    required: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not _TOOL_NAME.match(self.name):
            raise ValueError(f"invalid tool name {self.name!r}")


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _ok(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


class McpGuard:
    def __init__(self, gateway: Gateway, tools: List[Tool], limiter: Optional[RateLimiter] = None,
                 replay: Optional[ReplayGuard] = None, inspector: Optional[OutputInspector] = None):
        self.gateway = gateway
        self.limiter = limiter
        self.replay = replay
        self.inspector = inspector
        self._tools: Dict[str, Tool] = {}
        for t in tools:
            if t.name in self._tools:
                raise ValueError(f"duplicate tool {t.name!r}")
            self._tools[t.name] = t

    def handle_authenticated(self, request: Any, card: AgentCard) -> Dict[str, Any]:
        """Like :meth:`handle`, but the caller must prove possession of the agent's key.

        Use this whenever the transport does not already authenticate the caller.
        Order matters: card and pin are checked first, then the signature, then
        replay, so unauthenticated callers cannot fill the nonce cache.
        """
        if self.replay is None:
            raise RuntimeError("handle_authenticated requires a ReplayGuard")
        if not isinstance(request, dict):
            return _error(None, INVALID_REQUEST, "invalid request")
        req_id, audit = request.get("id"), self.gateway.audit
        if not verify_card(card) or not self.gateway.trust.is_pinned(card):
            audit.append("auth_failed", {"agent": card.agent_id, "why": "card"})
            return _error(req_id, AUTH_FAILED, "authentication failed")
        ok, why = verify_request(card, request)
        if not ok:
            audit.append("auth_failed", {"agent": card.agent_id, "why": why})
            return _error(req_id, AUTH_FAILED, "authentication failed")
        auth = request["auth"]
        ok, why = self.replay.check(card.agent_id, auth["nonce"], auth["ts"])
        if not ok:
            audit.append("replay_rejected", {"agent": card.agent_id, "why": why})
            return _error(req_id, REPLAYED, why)
        return self.handle(request, card)

    def handle(self, request: Any, card: AgentCard) -> Dict[str, Any]:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" \
                or not isinstance(request.get("method"), str):
            return _error(request.get("id") if isinstance(request, dict) else None,
                          INVALID_REQUEST, "invalid request")
        req_id, method = request.get("id"), request["method"]
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return _error(req_id, INVALID_PARAMS, "params must be an object")
        if method == "tools/list":
            return _ok(req_id, {"tools": self._list(card)})
        if method == "tools/call":
            return self._call(req_id, params, card)
        return _error(req_id, METHOD_NOT_FOUND, f"unknown method {method!r}")

    def _list(self, card: AgentCard) -> List[Dict[str, Any]]:
        out = []
        for t in self._tools.values():
            effect, _ = self.gateway.policy.evaluate(card.agent_id, tool_capability(t.name))
            if effect is not Effect.DENY:
                out.append({"name": t.name, "description": t.description})
        return out

    def _call(self, req_id: Any, params: Dict[str, Any], card: AgentCard) -> Dict[str, Any]:
        name, args = params.get("name"), params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(args, dict):
            return _error(req_id, INVALID_PARAMS, "name must be a string and arguments an object")
        tool = self._tools.get(name)
        if tool is None:
            return _error(req_id, INVALID_PARAMS, f"unknown tool {name!r}")
        if self.limiter is not None and not self.limiter.allow(card.agent_id):
            self.gateway.audit.append("rate_limited", {"agent": card.agent_id, "tool": name})
            return _error(req_id, RATE_LIMITED, "rate limit exceeded")
        try:
            inspect.signature(tool.handler).bind(**args)
        except TypeError as exc:
            return _error(req_id, INVALID_PARAMS, f"bad arguments: {exc}")
        missing = [k for k in tool.required if k not in args]
        if missing:
            return _error(req_id, INVALID_PARAMS, f"missing arguments: {', '.join(missing)}")
        self.gateway.audit.append("tool_args", {"agent": card.agent_id, "tool": name, "arg_names": sorted(args)})
        try:
            result = self.gateway.invoke(card, tool_capability(name), tool.handler, **args)
        except PermissionDenied as denied:
            return _error(req_id, PERMISSION_DENIED, denied.decision.reason)
        except Exception:
            return _error(req_id, INTERNAL, "tool failed")
        if self.inspector is not None:
            try:
                result, kinds = self.inspector.apply(result)
            except OutputBlocked as blocked:
                self.gateway.audit.append("output_blocked", {"agent": card.agent_id, "tool": name, "kinds": blocked.kinds})
                return _error(req_id, OUTPUT_BLOCKED, "tool output blocked by policy")
            if kinds:
                self.gateway.audit.append("output_flagged", {"agent": card.agent_id, "tool": name, "kinds": kinds})
                return _ok(req_id, {"content": result, "warnings": kinds})
        return _ok(req_id, {"content": result})
