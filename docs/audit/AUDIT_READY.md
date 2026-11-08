# arachne-guard 0.4.0 — Independent Security Review Package

**Status:** Prepared for external review  
**Date:** 2026-11-08  
**Scope:** Python reference implementation (library + tests)  
**Contact:** Mourad Soltani / https://github.com/Mourad-Soltani/arachne-guard

---

## 1. What this package contains

| Artifact | Purpose |
|----------|---------|
| `docs/THREAT_MODEL.md` | Self-assessed threat model (honest about gaps) |
| `docs/audit/AUDIT_READY.md` | This document — scope, surface, test evidence |
| `docs/audit/SECURITY_QUESTIONNAIRE.md` | Pre-filled answers for common audit questionnaires |
| `docs/audit/MUTATION_EVIDENCE.md` | Summary of mutation checks performed |
| `docs/audit/REVIEWER_CHECKLIST.md` | Suggested review priorities and known footguns |
| Full source + 99 unit tests | Reproducible under `python -m unittest discover -s tests -v` |

**Not included (and not claimed):** formal third-party audit report, formal verification, hardware key support, multi-process nonce store, production hardening for multi-tenant SaaS.

---

## 2. Trust claims (what we assert)

1. A public agent card alone is insufficient to call tools.  
   `handle_authenticated` requires a signature over (agent_id, method, params, id, nonce, ts) that verifies against the card’s embedded public key, which must also be pinned.

2. Replay of a previously accepted signed request is rejected inside the configured clock window, and the nonce cache fails closed when full.

3. Unauthenticated callers never reach the nonce cache (card → pin → signature are checked first).

4. Policy is default-deny; deny rules take precedence over ask/allow.

5. Consent gate fails closed (missing or crashing approver → deny).

6. Audit log is a hash chain; a signed checkpoint can detect truncation or whole-log rewrite *if* the checkpoint is stored outside the log’s trust domain.

7. Output inspection is **heuristic only** and is defence-in-depth, not a guarantee.

---

## 3. Attack surface (reviewer focus)

### Cryptographic
- Ed25519 card signing / verification (`identity.py`)
- Request signing / verification (`request_auth.py`)
- Canonical JSON encoding used for all signatures
- Key rotation statement + counter (anti-rollback)

### State & protocol
- `ReplayGuard` nonce cache + clock window
- `TrustStore` pin / rotate / revoke persistence (atomic write, 0600)
- `McpGuard.handle` vs `handle_authenticated` (the former is a documented footgun)

### Policy & consent
- Capability matching and default-deny evaluation order
- Consent gate failure modes

### Output
- Secret regexes and prompt-injection phrase heuristics (`outputscan.py`)

### Persistence
- Trust store file format and atomic replace
- Audit log hash chain and checkpoint signature

---

## 4. Explicit non-claims

- No hardware-backed keys (software Ed25519 only).
- Nonce state is in-process; not safe across processes/hosts without an external store.
- No discovery or inventory of “shadow” MCP servers.
- Output scanning is trivially evadable by a determined attacker.
- The plain `handle` method trusts the caller to have authenticated; misuse is possible.
- No formal verification, no constant-time claims beyond what the cryptography library provides, no side-channel assessment.

---

## 5. How to reproduce the test suite

```bash
git clone https://github.com/Mourad-Soltani/arachne-guard.git
cd arachne-guard
pip install cryptography
python -W error -m unittest discover -s tests -v
python demo.py
```

Expected: 99 tests OK, demo prints the documented scenario (including redacted secret, consent denial, replay rejection, unsigned rejection, checkpoint verification).

---

## 6. Suggested external review scope (minimal high-value)

1. Cryptographic binding of card and of request (canonical form, field coverage, type checks on `ts`).
2. Ordering of checks in `handle_authenticated` (especially that nonce cache is not reachable without a valid signature).
3. TrustStore atomicity and permission bits.
4. Policy evaluation order and default-deny.
5. Footgun surface of `handle` vs `handle_authenticated`.
6. Whether any test passes for the wrong reason (one such case was already found and fixed in 0.4.0).

A full formal audit is welcome; the above is the highest-ROI subset for a short engagement.

---

## 7. Licence and warranty

MIT. The software is provided “as is”. This package is a self-assessment aid, **not** a security certification.
