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

## Deployment (v1.1)

To fully cross the trust boundary, the verifier must be installed as a protected Windows service.

1. Open an **Elevated (Admin) PowerShell**.
2. Run `.\install_service.ps1`
   - This script creates `C:\ProgramData\AGYVerifier`.
   - It strips permissions and assigns Full Control *only* to `SYSTEM` and `Administrators`, explicitly denying the Antigravity agent process from tampering with the private key or modifying the ledger.
   - It registers a Scheduled Task to run the backend service as `NT AUTHORITY\SYSTEM` on startup.
   - Without running this, the trust boundary remains theoretical!

## Viewing the Ledger
Run `python agy_gui.py` to launch a local desktop application that reads the protected ledger and displays all generated cryptographic certificates and their signatures.
I deliberately passed the verifier failing scenarios to ensure it correctly denies certificates:
- **Fake endpoint**: Rejected with a `FAIL` status and the `Max retries exceeded` request error.
- **Uninitialized Git Repo**: Rejected the `pushed` claim with a `FAIL` because it failed to fetch the remote origin.
- **Fake PID**: Rejected the `running` claim with a `FAIL` and "Process with PID 99999 does not exist".

All results correctly exited with status 1 and appended to the `agy_verification_audit.jsonl` audit log.
