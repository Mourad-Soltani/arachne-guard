# Security Questionnaire (pre-filled for arachne-guard 0.4.0)

## Product overview
- **Name:** arachne-guard  
- **Version:** 0.4.0  
- **Type:** Open-source Python library (agent identity, authorization, audit for MCP/A2A)  
- **Licence:** MIT  
- **Repo:** https://github.com/Mourad-Soltani/arachne-guard  

## Cryptography
| Question | Answer |
|----------|--------|
| Algorithms used | Ed25519 (sign/verify), SHA-256 (audit chain hashes via hashlib) |
| Key generation | `cryptography` library Ed25519PrivateKey.generate() |
| Key storage | Caller-managed; library holds keys only in memory for the duration of the call. TrustStore persists *public* keys only. |
| Hardware keys | Not supported in 0.4.0 |
| Canonicalization for signatures | Deterministic JSON: sort_keys=True, separators=(",", ":"), ensure_ascii=False |
| Constant-time comparison | Relies on cryptography library; no custom secret comparison beyond signature verify |

## Authentication & authorization
| Question | Answer |
|----------|--------|
| Primary auth mechanism | Proof-of-possession: request signed with agent private key; card must be pinned |
| Replay protection | Yes — nonce + timestamp window; bounded cache, fails closed |
| Session / token lifetime | No long-lived sessions; each request is independently signed |
| Default policy | Deny |
| Consent | Explicit gate for “ask” decisions; fails closed |
| Multi-tenant isolation | Out of scope for the library; caller must isolate TrustStores / audit logs |

## Data handling
| Question | Answer |
|----------|--------|
| Secrets in logs | Tool *arguments* audited by name only; values are not written. Output inspector can redact known secret patterns from tool *results*. |
| PII | Not specifically modelled; treat as caller responsibility |
| Encryption at rest | TrustStore file is not encrypted; permissions set to 0600 on write |

## Testing & assurance
| Question | Answer |
|----------|--------|
| Automated tests | 99 unit tests |
| Mutation testing | Hand-crafted mutations on security-critical paths (see MUTATION_EVIDENCE.md); all caught |
| Independent audit | None yet — this package is prepared for one |
| Formal verification | None |
| Fuzzing | Not performed |

## Known limitations (must be disclosed)
1. `McpGuard.handle` trusts the transport; use `handle_authenticated`.
2. Output inspection is heuristic.
3. Nonce cache is in-process only.
4. No shadow-MCP discovery.
5. Software keys only.
6. Checkpoint is only useful if stored outside the log’s trust domain.

## Contact for security reports
Open a private security advisory on the repository or contact the maintainer.
Do not open public issues for unfixed vulnerabilities.
