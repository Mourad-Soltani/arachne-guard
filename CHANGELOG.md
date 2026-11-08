# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-08

### Added

- **Proof of possession** — `handle_authenticated` requires each request to be signed with the agent’s private key (`sign_request` / `verify_request`). A public card alone is no longer sufficient to call tools.
- **Replay protection** — `ReplayGuard` with a bounded nonce cache and clock window. Fails closed when the cache is full. Unauthenticated callers never reach the cache.
- **Audit checkpoints** — `AuditLog.checkpoint` / `verify_checkpoint` produce and verify a signed snapshot that detects truncation and whole-log rewrites (when stored outside the log’s trust domain).
- **Output inspection** — `OutputInspector` scans tool results for common secret patterns (AWS keys, GitHub tokens, bearer tokens, private keys, credential assignments) and prompt-injection phrasing. Supports redact / flag / block.
- Expanded test suite (99 tests) covering the new layers, plus targeted mutation checks on the security-critical paths.

### Changed

- Threat model and demo updated to reflect the new authentication and inspection layers.
- `McpGuard` now exposes both `handle` (legacy / transport-authenticated) and `handle_authenticated` (recommended).

### Security

- Closed the “anyone holding a public card can call tools” gap.
- Nonce cache is only consulted after card, pin and signature checks succeed.

## [0.3.x] and earlier

Internal development releases. Not published.
