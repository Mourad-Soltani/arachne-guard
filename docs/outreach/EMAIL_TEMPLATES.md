# Outreach email templates

## 1. Design partner (primary — use this first)

Subject: Design partner for cryptographic MCP / agent-auth library?

Hi {{name}},

I’m Mourad Soltani. I built arachne-guard — a small open-source library that puts proof-of-possession (Ed25519-signed requests), replay protection, default-deny policy, consent, and a hash-chained audit log in front of MCP tool calls.

The gap it closes: many MCP paths still treat a public agent card as enough. Anyone holding the card can call tools. arachne-guard requires the agent to sign every request.

- Repo: https://github.com/Mourad-Soltani/arachne-guard  
- v0.4.0, 99 tests, threat model + audit package ready for external review  
- Kotlin behavioural port started: https://github.com/Mourad-Soltani/arachne-guard-kotlin  

I’m looking for 2–3 design partners who will run it against a real agent or MCP gateway for a few weeks and tell me what breaks. No payment, no public commitment required — just direct access and influence on the next steps (Android Keystore path, hosted checkpoint plane).

If this is relevant to {{company}}’s agent-identity or MCP work, I’d welcome a short call.

Mourad  
https://github.com/Mourad-Soltani

---

## 2. Embed / platform team (slightly more commercial)

Subject: Embeddable proof-of-possession layer for agent / MCP tool calls

Hi {{name}},

Quick context: arachne-guard is an MIT-licensed Python library (Kotlin port in progress) that enforces:

- Signed agent requests (proof of possession, not just a public card)
- Replay protection
- Default-deny capability policy + fail-closed consent
- Tamper-evident audit + optional off-device checkpoints

It’s intentionally small (~900 LOC core) so it can sit inside a gateway or runtime rather than replace one.

Repo: https://github.com/Mourad-Soltani/arachne-guard  

If {{company}} is hardening MCP or agent tool-calling paths, I’m open to a design-partner engagement or a discussion about embedding the core. Happy to walk through the threat model and test suite on a call.

Mourad Soltani

---

## 3. Security review intro (for auditors / research teams)

Subject: Request for independent review — arachne-guard agent identity library

Hi {{name}},

I’ve prepared an audit package for arachne-guard (Ed25519 agent cards, request PoP, replay, policy, audit chain for MCP tool calls). Self-assessed threat model and mutation notes are in-repo under docs/audit/.

Repo: https://github.com/Mourad-Soltani/arachne-guard  

Would {{org}} be open to a scoped review (cryptographic binding + auth ordering + footguns)? Happy to share the checklist and answer questions first.

Mourad

---

## Tracking

| Date | Target | Channel | Template | Status |
|------|--------|---------|----------|--------|
|      |        |         |          |        |

## Sent log (2026-11-10)

| Date | Target | Address | Status |
|------|--------|---------|--------|
| 2026-11-10 | Aembit | info@aembit.io | Sent |
| 2026-11-10 | Descope | info@descope.com | Sent |
| 2026-11-10 | Keycard | help@keycard.ai | Sent |
