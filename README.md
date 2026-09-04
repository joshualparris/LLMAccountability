# LLMAccountability

LLMAccountability is an anti-tampering verification framework for AI coding-agent claims. It combines a protected Windows execution boundary with a V2 report-auditing layer that turns checkable completion claims into independently gathered evidence and signed attestations.

## Current status

V2 is implemented in the default branch; it is no longer only a roadmap.

The current V2 CLI can:

1. read a Markdown completion report,
2. deterministically extract supported claim wording,
3. ask the protected SYSTEM notary to independently run the applicable verification recipes,
4. evaluate the resulting evidence under a fail-closed policy, and
5. return a DSSE-wrapped in-toto statement signed by the notary's Ed25519 key.

The hardened Windows runtime from the v1.x work remains the execution foundation beneath V2.

## Trust boundary

### 1. SYSTEM Notary — `agy_service.exe`

Runs as `NT AUTHORITY\SYSTEM` on `127.0.0.1:8123`.

Responsibilities include:

- holding the Ed25519 private key under `C:\ProgramData\AGYVerifier`
- validating HMAC-authenticated evidence returned by the worker
- validating and appending signed, hash-chained certification records
- independently executing V2 recipes before signing `/v2/attest` results
- signing DSSE pre-authentication encoding (PAE), rather than signing caller-supplied verdicts

### 2. Trusted worker — `agy_worker.exe`

Runs under the restricted `AGYWorker` identity and exposes the local execution endpoint on port `8124`. It gathers structured command evidence and authenticates that evidence back to the notary with the worker secret.

### 3. Untrusted runner — `AGYRunner`

Verification commands are executed under the more restricted `AGYRunner` identity. The Windows installer creates the local identities, ACLs, protected runtime, scheduled tasks, and required logon rights.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the boundaries and non-goals.

## V2 claim auditing

The deterministic extractor currently recognises these report claim families:

- `tests-pass`
- `pushed`
- `no-secrets`
- `security-reviewed`
- `fully-complete`

Only `tests-pass` and `pushed` currently have V2 verification recipes. Recognised claims without a recipe are returned as `INCONCLUSIVE`; they are not silently treated as verified.

The policy engine returns `PASS`, `FAIL`, or `INCONCLUSIVE`. Missing evidence and partial evidence are not promoted to success. A `fully-complete` claim is denied when any claim is failed or inconclusive.

See [`docs/CLAIM_TYPES.md`](docs/CLAIM_TYPES.md) and [`docs/POLICY.md`](docs/POLICY.md).

## What the current recipes verify

### `tests-pass`

The `python-full` path requires more than a zero process exit code. The notary checks that:

- the command exited successfully
- at least one test was collected
- collected/passed/failed/error/skipped metrics are present, integer-valued, non-negative, and internally consistent
- there are zero failures and zero errors
- a workspace fingerprint and file count are present
- the protected Python runtime was used
- the Python executable hash is present
- the pytest version is known

### `pushed`

The Git recipe gathers local and remote Git evidence and only passes when it can establish the required SHAs and the local HEAD, upstream state, and remote lookup agree. Prerequisite/network failures are `INCONCLUSIVE`, not success.

## CLI

Install Python dependencies first:

```powershell
python -m pip install -r requirements.txt
```

Audit a completion report:

```powershell
python agy.py audit-report final-report.md --repo-path C:\dev\MyRepo --test-profile python-full
```

Fail the process unless the final policy verdict is `PASS`:

```powershell
python agy.py audit-report final-report.md --repo-path C:\dev\MyRepo --test-profile python-full --enforce
```

The CLI expects the protected notary/worker services to be installed and running.

## Windows installation

Run from an elevated Administrator PowerShell prompt:

```powershell
.\install_service.ps1
```

For installer/preflight behaviour, read the script before deployment. The installation changes local users, ACLs, logon rights, protected runtime files, and scheduled tasks.

## Service interfaces

The current notary exposes local-only endpoints including:

- `GET /ledger` — read certification records
- `POST /certify` — v1-style protected certification for supported operational claims
- `POST /v2/execute` — gather and authenticate worker evidence for a V2 recipe
- `POST /v2/attest` — independently execute supported recipes, evaluate policy, and return a signed DSSE/in-toto attestation

The v1-style `/certify` path currently handles `pushed`, `tests-pass`, `running`, and `endpoint-working` claims.

## Tests

The repository includes adversarial and regression coverage for V2 policy/recipe behaviour, runner behaviour, sanitisation, pytest report-log evidence, and the elevated Windows `SeBatchLogonRight` path.

Run the Python test suite from an environment with the required dependencies:

```powershell
pytest
```

Some Windows integration/elevated tests require the corresponding Windows environment and privileges; a green unit-test run is not a substitute for physical deployment validation.

## Security notes

LLMAccountability is designed to make self-reported agent success harder to fake, not to prove arbitrary semantic correctness.

Key properties in the current implementation include:

- separate notary, worker, and runner identities
- authenticated worker-to-notary evidence
- Ed25519-signed certification records
- hash-chain validation before new `/certify` records are accepted
- V2 notary-side recipe execution and policy evaluation before attestation signing
- fail-closed handling of missing, malformed, inconsistent, or unsupported evidence

Important limitations are documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Design references

See [`docs/OPEN_SOURCE_FEATURE_HARVEST.md`](docs/OPEN_SOURCE_FEATURE_HARVEST.md) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for upstream ideas and attribution.
