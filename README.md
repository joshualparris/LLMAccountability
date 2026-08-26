# LLMAccountability

LLMAccountability is a rigorous, anti-tampering verification framework for AI coding agents.

## Architecture (v1.7)

The core mechanism is a **Three-Tier Trust Boundary** designed to completely isolate the entity performing verification from the untrusted code being tested. 

1.  **SYSTEM Notary (`agy_service.exe`)**: 
    Runs as `NT AUTHORITY\SYSTEM`. Holds the Ed25519 private key. It receives structured evidence payloads, validates HMAC signatures from the Broker, and appends cryptographically signed certificates to an append-only protected ledger.
2.  **Trusted Broker (`agy_worker.exe`)**: 
    Runs as a restricted `AGYWorker` local account. Holds the HMAC `worker_secret.key`. It orchestrates verification by spawning OS-level processes natively. 
3.  **Untrusted Runner (`AGYRunner` identity)**:
    A severely restricted, ephemeral execution identity. The Broker uses `System.Diagnostics.ProcessStartInfo` to dynamically spawn verification tasks (like `pytest` or `npm`) precisely as this `AGYRunner` user, completely isolating the untrusted code from the cryptographic secrets held by the Broker.

## Installation

Ensure you have reviewed the source code.
1. Run `install_service.ps1` from an elevated Administrator PowerShell prompt.
2. This establishes the strict OS-level ACLs, generates the local users (`AGYWorker`, `AGYRunner`), bootstraps the cryptographic secrets safely, and starts the Notary and Broker Scheduled Tasks.

## Moving to V2

We are actively transitioning from the v1.x trust-boundary prototyping into v2: an evidence-backed final-answer auditing system. V2 integrates concepts from `agent-verify`, `agent-execution-harness`, `proof-agent`, `in-toto`, and `Open Policy Agent` into a comprehensive verification suite for autonomous agents.

See `docs/OPEN_SOURCE_FEATURE_HARVEST.md` and `THIRD_PARTY_NOTICES.md` for details on our upstream architectural influences.
