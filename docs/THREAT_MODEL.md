# Threat model (v0.4, self-assessed, NOT independently reviewed)

| Threat | Status | Notes |
|---|---|---|
| Forged or tampered agent card | Covered | Ed25519 verify + pinned key + declared-capability check |
| Calling tools with only a *public* card | Covered (via `handle_authenticated`) | Requests are signed; signature bound to agent id, method, params, id, nonce, ts |
| Replay of a captured request | Covered (via `handle_authenticated`) | Nonce cache + clock window; bounded, fails closed when full |
| Unauthenticated callers exhausting the nonce cache | Covered | Card, pin and signature are checked before the cache is touched |
| Old/stolen key after rotation | Covered | Rotation needs a statement signed by the current key; counter blocks replay incl. A->B->A |
| Revoked agent returns | Covered | Revocation is permanent and persisted |
| Privilege escalation via tool calls | Covered | Default-deny policy, deny > ask > allow, per-tool capability |
| Consent bypass | Covered | Missing or crashing approver denies |
| Audit edit/delete/reorder | Covered | Hash chain verified on load and on demand |
| Audit truncation or whole-log rewrite | Covered IF the signed checkpoint is stored outside the log's trust domain | `checkpoint` / `verify_checkpoint`; nothing here stores it for you |
| Secrets in tool output | Partial | Regex heuristics (AWS, GitHub, bearer, private key, credential assignments); redact/flag/block |
| Prompt injection via tool responses | Partial | Phrase heuristics only; flag or block. Trivially evadable by a determined attacker |
| Unauthenticated `McpGuard.handle` misuse | **Footgun** | `handle` trusts the caller to have authenticated; use `handle_authenticated` unless the transport does |
| Shadow / unregistered MCP servers | NOT covered | Guard only fronts tools it is given; no discovery or inventory |
| Key theft from the host | NOT covered | Software keys; Android Keystore / hardware backing not implemented |
| Denial of service | Partial | Per-agent-id rate limit; replay cache bounded |
| Multi-process / multi-host replay state | NOT covered | Nonce cache is in-process memory |
| Side channels, supply chain, protocol fuzzing | Not assessed | |
