"""End-to-end demo: a signed agent calls MCP tools through the guard."""
from arachne_guard import (
    AgentCard, ConsentGate, Gateway, McpGuard, OutputInspector, Policy, RateLimiter, ReplayGuard,
    Tool, TrustStore, generate_keypair, policy_from_dict, public_key_b64, sign_card, sign_request,
)

key = generate_keypair()
card = sign_card(AgentCard(agent_id="trip-agent", name="Trip", version="1",
                           capabilities=frozenset({"mcp.call:*"})), key)
trust = TrustStore()
trust.pin(card.agent_id, card.public_key)

policy = policy_from_dict({"rules": [
    {"effect": "allow", "capability": "mcp.call:weather"},
    {"effect": "allow", "capability": "mcp.call:notes"},
    {"effect": "ask", "capability": "mcp.call:read_contacts"},
]})
# The approver stands in for a UI prompt; this demo's user declines every request.
gateway = Gateway(trust, policy, ConsentGate(lambda agent, cap: False))
guard = McpGuard(gateway, [
    Tool("weather", "forecast", lambda city: f"sunny in {city}", required=["city"]),
    Tool("notes", "notes", lambda: "todo: password = hunter2hunter2hunter2"),
    Tool("read_contacts", "contacts", lambda: ["alice", "bob"]),
    Tool("delete_all", "danger", lambda: "gone"),
], RateLimiter(10, 60), ReplayGuard(), OutputInspector())

def rpc(method, signed=True, **params):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    if signed:
        request = sign_request(key, card.agent_id, request)
    return request, guard.handle_authenticated(request, card)

print("list       :", [t["name"] for t in rpc("tools/list")[1]["result"]["tools"]])
print("weather    :", rpc("tools/call", name="weather", arguments={"city": "Tunis"})[1]["result"])
print("notes      :", rpc("tools/call", name="notes")[1]["result"])
print("contacts   :", rpc("tools/call", name="read_contacts")[1]["error"]["message"])
print("delete_all :", rpc("tools/call", name="delete_all")[1]["error"]["message"])
sent, _ = rpc("tools/call", name="weather", arguments={"city": "Sfax"})
print("replayed   :", guard.handle_authenticated(sent, card)["error"]["message"])
print("unsigned   :", rpc("tools/list", signed=False)[1]["error"]["message"])

checkpoint = gateway.audit.checkpoint(key)      # in real use: ship this off-device
print("audit      :", gateway.audit.verify_checkpoint(checkpoint, public_key_b64(key)),
      f"({len(gateway.audit.entries)} entries)")
