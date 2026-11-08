# Reviewer checklist — arachne-guard 0.4.0

## Critical path (do these first)

- [ ] Canonical JSON: confirm every signed field is included and that key order / separators match the implementation used at verify time.
- [ ] `verify_request` type checks: boolean `ts` must be rejected before numeric conversion; nonce length bounds enforced.
- [ ] Ordering inside `handle_authenticated`: signature and pin checks occur *before* any write to the replay cache.
- [ ] Replay cache: fails closed at `max_entries`; eviction only removes expired entries.
- [ ] TrustStore: atomic replace, mode 0600, corrupt file raises rather than silently trusting.
- [ ] Rotation: counter strictly increases; statement must be signed by the *current* pinned key.
- [ ] Policy: deny > ask > allow; default deny when no rule matches.
- [ ] Consent: exception or missing approver → deny.
- [ ] `handle` vs `handle_authenticated`: document and, if possible, make misuse harder (deprecation warning, rename, or require an explicit “I authenticated the transport” flag).

## Secondary

- [ ] Output inspector: confirm it never *allows* a secret through when in block mode; treat heuristics as non-security-critical.
- [ ] Audit checkpoint: verify that a checkpoint that does not cover the current head is rejected; confirm the signature binds the head hash and length.
- [ ] Rate limiter: per-agent-id, does not become a DoS vector against the process itself under normal use.
- [ ] Capability pattern validation: no path-traversal style patterns accepted.

## Out of scope for a short review (but note if observed)

- Side channels, timing, cache effects
- Supply-chain / dependency audit beyond `cryptography`
- Multi-process nonce design
- Android Keystore / hardware keys
- Shadow MCP discovery

## Deliverable request

A short written opinion covering:
1. Whether the claims in `AUDIT_READY.md` §2 hold under the examined code.
2. Any finding that would allow an unauthenticated or incorrectly authenticated caller to execute a tool or to exhaust the replay cache.
3. Residual risk list (even if “accepted”).
