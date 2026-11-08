# arachne-guard — Design Partner Brief (1 page)

**What it is**  
A small, tested Python library that puts cryptographic identity, proof-of-possession, default-deny policy, consent, and a tamper-evident audit log in front of MCP / agent tool calls.

**The problem it closes**  
Today many MCP servers accept a public agent card as sufficient. Anyone who obtains the card can call tools. arachne-guard requires every request to be signed with the agent’s private key, rejects replays, and records every decision in a hash chain.

**What you get as a design partner**
- Direct line to the maintainer for the duration of the engagement
- Influence on the roadmap (Kotlin/Android path, hosted control plane, policy language)
- Early access to the independent-review findings once they exist
- Attribution (optional) and a case study if you want one

**What we ask**
- Run the library in a real (or realistic) agent/MCP path for 2–4 weeks
- Report breakage, missing affordances, and any security concern
- 30–45 min debrief call

**Not asking for**
- Payment
- Public endorsement unless you choose to give one
- Production traffic on day one

**Current status (2026-11)**  
v0.4.0 public: https://github.com/Mourad-Soltani/arachne-guard  
99 tests, mutation checks on critical paths, threat model published, audit package ready for external review.  
Kotlin behavioural skeleton: https://github.com/Mourad-Soltani/arachne-guard-kotlin

**Contact**  
Open an issue with the label `design-partner` or email via the GitHub profile.

---

## Ideal partner profile
- Building or operating MCP servers / agent runtimes
- Security or platform team that already cares about non-human identity
- Willing to try a small library without a full SaaS commitment
- Can give concrete feedback on API shape and missing pieces
