# arachne-guard

**Identity, permissions, consent and tamper-evident audit for AI agents (MCP / A2A).**

A small, well-tested Python library that sits in front of tool-calling surfaces so that every agent action is authenticated, authorized, consented (when required) and recorded in a hash-chained audit log.

```bash
pip install arachne-guard
```

## Why it exists

Public agent cards are not enough. Anyone who obtains a card can currently impersonate the agent on many MCP servers. arachne-guard closes that gap and several others:

- **Proof of possession** — every request must be signed with the agent’s private key
- **Replay protection** — bounded nonce cache + clock window (fails closed when full)
- **Default-deny policy** with deny > ask > allow and a consent gate that fails closed
- **Tamper-evident audit** — hash chain + optional signed checkpoints
- **Output inspection** — heuristic redaction/blocking of secrets and prompt-injection phrasing

It is intentionally small (~900 lines of library code) so it can be reviewed and ported.

## Quick start

```python
from arachne_guard import (
    AgentCard, ConsentGate, Gateway, McpGuard, OutputInspector,
    RateLimiter, ReplayGuard, Tool, TrustStore,
    generate_keypair, policy_from_dict, sign_card, sign_request,
)

# 1. Agent identity
key = generate_keypair()
card = sign_card(
    AgentCard(
        agent_id="trip-agent",
        name="Trip",
        version="1",
        capabilities=frozenset({"mcp.call:*"}),
    ),
    key,
)

# 2. Trust + policy
trust = TrustStore()
trust.pin(card.agent_id, card.public_key)

policy = policy_from_dict({
    "rules": [
        {"effect": "allow", "capability": "mcp.call:weather"},
        {"effect": "ask",   "capability": "mcp.call:read_contacts"},
    ]
})

gateway = Gateway(trust, policy, ConsentGate(lambda agent, cap: False))  # deny all asks

# 3. Guard the tools
guard = McpGuard(
    gateway,
    [
        Tool("weather", "forecast", lambda city: f"sunny in {city}", required=["city"]),
        Tool("read_contacts", "contacts", lambda: ["alice", "bob"]),
    ],
    RateLimiter(10, 60),
    ReplayGuard(),
    OutputInspector(),
)

# 4. Every call must be signed
request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "weather", "arguments": {"city": "Tunis"}},
}
signed = sign_request(key, card.agent_id, request)
result = guard.handle_authenticated(signed, card)
print(result)
```

Run the full demo:

```bash
python demo.py
```

## How a request is checked

`Gateway` (and therefore `McpGuard.handle_authenticated`) evaluates, in order:

1. Capability string is syntactically valid
2. Agent card signature verifies (Ed25519 over canonical JSON)
3. Card’s public key is pinned in the `TrustStore`
4. Capability is declared on the card
5. Policy decision (deny > ask > allow; default deny)
6. Consent gate for `ask` (missing/crashing approver → deny)
7. Hash-chained audit entry for every decision

Additionally for authenticated MCP calls:

- Request signature binds agent id, method, params, id, nonce and timestamp
- Replay cache rejects seen nonces inside the clock window
- Tool arguments are checked against the declared signature
- Tool output is scanned for secrets / injection phrases
- Rate limit is applied per agent id

## Security model (summary)

| Threat | Status |
|--------|--------|
| Forged / tampered agent card | Covered |
| Acting with only a public card | Covered (`handle_authenticated`) |
| Replay of a captured request | Covered |
| Exhausting the nonce cache unauthenticated | Covered |
| Key rotation / revocation | Covered |
| Privilege escalation via tools | Covered (default deny) |
| Consent bypass | Covered (fails closed) |
| Audit edit / reorder / truncation | Covered *if* the checkpoint is stored outside the log’s trust domain |
| Secrets / prompt injection in tool output | Partial (heuristics) |
| Shadow / unregistered MCP servers | **Not covered** |
| Key theft from the host | **Not covered** (software keys) |
| Multi-process / multi-host nonce state | **Not covered** |

Full details: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**This is a reference implementation. It has not been independently audited.**

## Installation & development

```bash
pip install arachne-guard          # runtime
pip install -e ".[dev]"            # editable + build tools
python -m unittest discover -s tests -v
python demo.py
```

Requires Python ≥ 3.9 and `cryptography ≥ 42`.

## Kotlin / Android

Kotlin behavioural port: https://github.com/Mourad-Soltani/arachne-guard-kotlin  
Android Keystore path and proof bar: [docs/ANDROID.md](https://github.com/Mourad-Soltani/arachne-guard-kotlin/blob/main/docs/ANDROID.md) in that repo.

## Independent review & design partners

- **Audit package** (ready for external reviewer): [`docs/audit/`](docs/audit/)
- **Design partner brief**: [`docs/partners/DESIGN_PARTNER_PITCH.md`](docs/partners/DESIGN_PARTNER_PITCH.md)
- Open an issue with label `design-partner` if you want to run it in a real agent/MCP path.

## Commercial (deferred)

Hosted policy + off-device checkpoint plane is designed but **not built** until there are real users. See [`docs/commercial/HOSTED_PLANE.md`](docs/commercial/HOSTED_PLANE.md).

## Licence

MIT. See [LICENSE](LICENSE).

## Status

- Version: **0.4.0**
- Tests: 99 passing
- Mutation checks on the security-critical paths: all caught
- Not independently audited
- Not production-ready for high-assurance environments without review
