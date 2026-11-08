# Mutation evidence (0.4.0)

Hand-crafted mutations were applied to security-critical paths after the 99-test suite was green. Each mutation was expected to make at least one test fail. All did.

## Categories exercised

### Request authentication (`request_auth.py`)
- Drop or alter one field from the signed payload (agent_id, method, params, nonce, ts)
- Accept boolean `ts` (JSON quirk) — previously a test was passing for the wrong reason; isolated type-check test added
- Swap signature for a different key
- Truncate or corrupt base64 signature / public key

### Replay (`replay.py`)
- Re-use the same nonce inside the window
- Accept nonce outside length bounds
- Accept non-numeric / boolean timestamp
- Force cache full and confirm fail-closed
- Advance clock past window and confirm old nonce is no longer remembered (and new one with old ts is rejected by window)

### Trust & cards (`identity.py`)
- Tamper any signed card field after signing
- Present a self-consistent card whose public key is not pinned
- Rotation signed by the wrong key
- Rotation with non-increasing counter
- Revoked agent attempting to act or to re-pin

### Policy & gateway
- Deny rule co-existing with allow for the same capability → deny wins
- Missing consent approver or raising approver → deny
- Capability not declared on card → deny even if policy would allow

### Audit
- Truncate the log and present an old checkpoint → verification fails
- Rewrite an entry while keeping the outer checkpoint → fails if checkpoint covers the chain head

## Process note
Mutations were applied one at a time from a clean tree, tests re-run, then reverted. No automated mutation framework was used; the goal was coverage of the properties claimed in the threat model rather than line coverage percentage.

A future external review should treat these as a starting set, not an exhaustive guarantee.
