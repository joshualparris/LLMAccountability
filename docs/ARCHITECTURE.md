# Architecture

LLMAccountability has two layers that work together:

1. a protected Windows execution/certification boundary, developed through the v1.x work; and
2. a V2 final-report auditing layer that extracts claims, independently verifies the supported ones, applies policy, and returns a signed attestation.

## Components

### SYSTEM notary — `agy_service.py` / `agy_service.exe`

The notary listens only on `127.0.0.1:8123` and is intended to run as `NT AUTHORITY\SYSTEM`.

Protected state lives under `C:\ProgramData\AGYVerifier`, including:

- `private.pem` — Ed25519 private key
- `public.pem` — Ed25519 public key
- `worker_secret.key` — HMAC secret shared with the trusted worker
- `protected_ledger.jsonl` — signed, hash-chained certification records

The notary is the trust decision point. It does not accept a caller-supplied PASS verdict as authoritative.

### Trusted worker — `agy_worker.py` / `agy_worker.exe`

The worker listens on `127.0.0.1:8124` and is intended to run under the restricted `AGYWorker` identity.

It:

- receives structured execution requests from the notary
- launches verification commands as `AGYRunner`
- gathers structured evidence
- sanitises diagnostic output for common credential formats
- adds a job nonce
- HMAC-signs the evidence before returning it to the notary

### Untrusted execution identity — `AGYRunner`

Verification commands execute under the separate `AGYRunner` account rather than under SYSTEM or the notary identity. The worker launches the process with an explicit executable, arguments, working directory, and credentials.

For the `python-full` profile, tests run with the protected Python executable at:

`C:\ProgramData\AGYRuntime\python\Scripts\python.exe`

The worker records its SHA-256 and generates a workspace fingerprint over relevant source, test, build, configuration, and lock files.

## V1-style certification flow

`POST /certify` supports operational claims including:

- `pushed`
- `tests-pass`
- `running`
- `endpoint-working`

Flow:

1. The notary validates the existing ledger before taking a new certification action.
2. The notary sends a structured execution request to the worker.
3. The worker runs the applicable commands as `AGYRunner` and returns HMAC-authenticated evidence.
4. The notary rejects missing/invalid worker authentication.
5. The notary applies claim-specific validation rules.
6. The resulting PASS/FAIL record is linked to the previous ledger hash, assigned a certificate ID, signed with Ed25519, and appended to the ledger.

A certification failure is still recorded as a signed record; failure does not disappear from the evidence trail.

## V2 report-auditing flow

The user-facing entry point is:

```powershell
python agy.py audit-report final-report.md --repo-path C:\dev\MyRepo --test-profile python-full
```

Flow:

1. `ClaimExtractor` scans the report for known claim wording and produces deterministic claim IDs.
2. The CLI sends the extracted claims and repository context to `POST /v2/attest`.
3. The SYSTEM notary chooses the recipe for each supported claim. The caller does not provide recipe results.
4. A recipe calls `POST /v2/execute` to gather fresh worker evidence.
5. `/v2/execute` authenticates the worker HMAC before returning evidence as authenticated.
6. The recipe converts evidence into `PASS`, `FAIL`, or `INCONCLUSIVE`.
7. `PolicyEngine` evaluates all extracted claims together.
8. `InTotoAttestation` creates an in-toto Statement v1 inside a DSSE envelope.
9. The notary signs the DSSE PAE with its Ed25519 private key and returns the envelope.

This design prevents `/v2/attest` from acting as a generic signing oracle for arbitrary caller-provided verdicts.

## Current V2 recipe coverage

Implemented recipes:

- `tests-pass` → `TestsPassRecipe`
- `pushed` → `GitPushRecipe`

The extractor also recognises `no-secrets`, `security-reviewed`, and `fully-complete`, but there is no dedicated verification recipe for those claim types yet. `/v2/attest` assigns them `INCONCLUSIVE` rather than treating them as verified.

## Tests-pass evidence

For `python-full`, evidence includes the pytest process result plus structured test metrics. The notary requires:

- successful process exit
- collected tests greater than zero
- integer, non-negative test counts
- zero failures and errors
- counts that add up consistently
- workspace fingerprint and file count
- the exact protected Python executable path
- Python executable SHA-256
- a known pytest version

The worker uses pytest report-log evidence rather than trusting a free-form success string.

`npm-full` exists as an execution profile, but its evidence validation is less specialised than the `python-full` path.

## Pushed evidence

Git verification gathers evidence for local repository state and the remote branch. The current path uses commands such as:

- `git remote get-url origin`
- `git status --porcelain`
- `git rev-parse --abbrev-ref HEAD`
- `git rev-parse HEAD`
- `git ls-remote origin refs/heads/<branch>`

The V2 recipe treats command/network/prerequisite failures as `INCONCLUSIVE`. A mismatch between established local and remote SHAs is `FAIL`.

## Cryptographic records

There are two related signed forms:

### Certification ledger records

`/certify` records are:

- hash-linked to the previous record
- assigned an `AGY-YYYYMMDD-<hash-prefix>` certificate ID
- Ed25519-signed
- revalidated before a new `/certify` action proceeds

### V2 attestations

`/v2/attest` returns a DSSE envelope whose payload is an in-toto Statement v1 using the local predicate type:

`https://llmaccountability.local/verification/v1`

The predicate contains extracted claims, recipe verdicts/evidence, and the policy evaluation. The notary signs the DSSE PAE with key ID `agy-ed25519-notary`.

## Installation architecture

`install_service.ps1` is the Windows deployment entry point. It establishes the local accounts, ACLs, logon rights, protected runtime material, and scheduled-task/service execution needed for the boundary.

Because installation changes Windows security state, run and review it from an elevated Administrator PowerShell session. Some integration checks require elevation and a real Windows installation; they are not equivalent to ordinary unit tests.

## Boundary summary

| Layer | Intended identity | Trust role |
| --- | --- | --- |
| Notary | `NT AUTHORITY\SYSTEM` | Holds signing key, authenticates evidence, evaluates/signs results |
| Worker | `AGYWorker` | Orchestrates evidence collection and HMAC-authenticates it |
| Runner | `AGYRunner` | Executes untrusted verification commands with reduced privileges |
| Audited agent/report | untrusted | May propose claims, but cannot authoritatively grade them |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what this architecture does and does not defend against.
