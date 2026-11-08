# Thin commercial offering — Hosted Policy & Audit Plane (design)

**Status:** Design only. Do not build until the library has real users / design partners.

## Goal
A minimal hosted control plane that sits *beside* the open-source library, not on top of it:

- Library remains MIT and fully usable offline.
- Hosted plane adds: central policy distribution, off-device audit checkpoints, optional consent UI webhook, usage visibility.

## Principles
1. The private key never leaves the agent runtime.
2. The library works with zero cloud dependency.
3. Hosted features are pure upside (better ops, multi-agent visibility), not required for security claims.

## Surfaces

### 1. Policy distribution
- Agent runtime periodically pulls a signed policy document for its agent_id (or team).
- Signature verified against a published control-plane public key.
- Offline fallback: last known good policy or local default-deny.

### 2. Checkpoint sink
- Runtime posts the signed audit checkpoint (head hash + length + sig) to the plane.
- Plane stores it out-of-band from the agent’s log storage → satisfies the “checkpoint outside trust domain” requirement.
- Optional: plane can later request a full log for investigation (with explicit operator action).

### 3. Consent webhook
- For `ask` decisions, library can call a configured HTTPS endpoint.
- Plane shows a simple approve/deny UI (or forwards to Slack / email).
- Timeout → deny (matches fail-closed behaviour).

### 4. Read-only console
- List agents, last checkpoint time, recent deny/ask counts.
- No ability to extract private keys or to rewrite history.

## Non-goals for v1
- Hosting the agent itself
- Becoming an MCP gateway
- Replacing enterprise IdPs (Okta / Entra / Descope)
- Complex multi-tenant RBAC beyond “owner can see their agents”

## Pricing sketch (only after demand exists)
- Free: open-source library forever.
- Hosted: per-agent or per-checkpoint tiers in the $20–$50/agent/month band (aligned with Aembit-style pricing), with a small free tier for design partners.
- Enterprise: SSO, SIEM export, custom retention — quote.

## Build trigger
Do not implement until at least one of:
- 2+ design partners asking for central policy or off-device checkpoints, or
- Clear inbound demand from the public repo / outreach.

## Implementation sketch (when triggered)
- Small FastAPI / Cloudflare Worker backend
- Postgres for checkpoints + policy versions
- Ed25519 key for plane-signed policies
- Stripe or Lemon Squeezy for billing
- Same threat-model honesty: document that the plane is an availability and ops layer, not the root of trust for agent keys.
