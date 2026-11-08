# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | Yes                |
| < 0.4   | No                 |

## Reporting a Vulnerability

Please open a private security advisory on the repository or contact the maintainer directly.

Do **not** open a public issue for security-sensitive reports until a fix or coordinated disclosure plan exists.

## Known Limitations (do not file as bugs)

These are intentional scope boundaries documented in `docs/THREAT_MODEL.md`:

- **`McpGuard.handle` is a footgun.** It assumes the transport has already authenticated the caller. Prefer `handle_authenticated` unless you control the transport and have verified identity yourself.
- **Output inspection is heuristic.** Secrets and prompt-injection phrasing can be evaded by a determined attacker. Treat it as defence-in-depth, not a guarantee.
- **No hardware-backed keys.** Keys live in process memory / software keystores. Android Keystore / Secure Enclave integration is future work.
- **Nonce cache is in-process.** Multi-process or multi-host deployments need an external shared store; the current `ReplayGuard` does not provide one.
- **No discovery of shadow MCP servers.** The guard only protects the tools you hand it.
- **Audit checkpoints must be stored out-of-band.** A checkpoint written into the same log it protects is useless against a full rewrite.

## Threat Model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the current self-assessment. This project has **not** been independently audited.

## Preferred Practice

1. Always use `handle_authenticated` for untrusted callers.
2. Store the private key with the strongest isolation available on the platform.
3. Persist the audit checkpoint somewhere the log writer cannot modify.
4. Treat policy as the primary control surface; keep the set of allowed capabilities minimal.
5. Rotate keys when an agent is decommissioned or suspected of compromise; revocation is permanent.
