# Antigravity Accountability Framework

The framework has been completely rewritten into an independent Certification Authority to structurally require independent evidence before Antigravity can claim success.

## What was built
1. **The Certification Authority CLI (`agy_verifier.py`)**: A Python script using standard `argparse` that acts as the sole source of observed evidence. It accepts claims and validates them structurally. To provide provenance and detect covert modification, it hashes its own source code and includes `verifier_hash` in the certificate.
2. **The Enforcement Rule (`strict_verification.md`)**: An `always_on` Antigravity rule instructing the model that it is strictly forbidden from claiming success without obtaining a Certificate ID from the CLI first.
3. **Hash-Chained Audit Trail**: Every certification attempt is recorded in `agy_verification_audit.jsonl`. Each record calculates a SHA-256 hash of its own contents combined with the hash of the previous record, making the log cryptographically tamper-evident.

## How it works
Rather than simply checking assertions, the agent must ask the verifier to "certify" a claim. The verifier dictates the evidence required.

```bash
# Example agent action to prove tests pass
python agy_verifier.py certify --claim tests-pass --test-command "pytest tests/"
```

If the verifier is satisfied, it outputs machine-readable JSON containing the Certificate ID and the collected evidence:
```json
{
  "timestamp": "2026-08-26T02:30:00Z",
  "certificate_id": "AGY-20260826-1a2b3c4d",
  "claim": "tests-pass",
  "status": "PASS",
  "evidence": {
    "command": "pytest tests/",
    "commit_sha": "8a912...",
    "exit_code": 0
  }
}
```

Antigravity is then forced by its rules to output:
> Tests pass — **AGY-20260826-1a2b3c4d PASS**

## Architectural Limitations & Trust Boundary (v0.4+)

While the ledger is cryptographically tamper-evident, this framework currently operates within the same trust domain as the agent. Because the agent executes the verifier and controls the environment:
1. **Ledger Substitution:** An agent could theoretically modify the script to point to a fresh ledger.
2. **Ledger Rewrite:** An adversary with write access could rewrite an old record, recompute all subsequent hashes, and replace the entire ledger.
3. **Lack of Trust Anchor:** The `verifier_hash` proves provenance, but there is no external trust anchor enforcing a known-good hash.

To achieve genuine non-repudiation, a strict **trust boundary** is required:
* The verifier must run as a protected, independent service (e.g., a protected Windows service).
* The ledger must be write-only to the agent.
* Certificates must be cryptographically signed (HMAC) by the service using a secret key inaccessible to the agent.
I deliberately passed the verifier failing scenarios to ensure it correctly denies certificates:
- **Fake endpoint**: Rejected with a `FAIL` status and the `Max retries exceeded` request error.
- **Uninitialized Git Repo**: Rejected the `pushed` claim with a `FAIL` because it failed to fetch the remote origin.
- **Fake PID**: Rejected the `running` claim with a `FAIL` and "Process with PID 99999 does not exist".

All results correctly exited with status 1 and appended to the `agy_verification_audit.jsonl` audit log.
