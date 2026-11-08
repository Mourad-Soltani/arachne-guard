# Design-partner outreach

## Short email / LinkedIn template

Subject: Design partner for agent identity / MCP auth library?

Hi {{name}},

I’m building arachne-guard — a small open-source library that forces proof-of-possession (signed requests), replay protection, default-deny policy and a hash-chained audit log in front of MCP tool calls.

The gap it targets is the common “public agent card is enough” pattern.

It’s at v0.4.0 (99 tests, threat model, audit package ready). I’m looking for 2–3 design partners who will run it against a real agent/MCP path for a few weeks and tell me what breaks or is missing.

No payment, no public commitment required. Direct access to me and influence on the next steps (Kotlin path, hosted plane).

Repo: https://github.com/Mourad-Soltani/arachne-guard  
One-pager: https://github.com/Mourad-Soltani/arachne-guard/blob/main/docs/partners/DESIGN_PARTNER_PITCH.md

If this is relevant to your team I’d be glad to jump on a short call.

— Mourad

## Target categories (prioritised)

1. **MCP server / gateway builders**  
   Teams behind open or commercial MCP gateways, registries, or runtimes who already think about auth.

2. **Agent platform / orchestration**  
   Companies shipping multi-agent or tool-calling products that need per-agent identity and audit.

3. **Security / NHI-focused startups and teams**  
   Non-human identity, agent identity, or AI TRiSM teams that want a cryptographic core they can embed rather than rebuild.

4. **Individual security researchers / auditors**  
   People who review agent security and might both use the library and later perform or recommend the independent review.

## Tracking

Keep a simple private list:

| Org / person | Channel | Status | Notes |
|--------------|---------|--------|-------|
|              |         |        |       |

Update status: contacted → replied → call booked → active partner → feedback received → closed.
