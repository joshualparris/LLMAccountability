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

## Deployment (v1.3)

This architecture uses strict **Separation of Concerns (Two Privilege Levels)** to prevent SYSTEM privilege escalation:
1. **Unprivileged Verification Worker (`agy_verifier.py`)**: Runs under the agent's standard account. It executes untrusted code (like `pytest` or `npm test` inside the project repo) and formats the structured evidence.
2. **Protected SYSTEM Service (`agy_service.exe`)**: Runs as `NT AUTHORITY\SYSTEM`. It does not execute untrusted project code. It cryptographically validates the evidence, enforces ledger integrity, and signs the certificates.

To fully cross the trust boundary, the verifier must be installed as a protected Windows service using a frozen Python runtime to prevent dependency hijacking.

1. Freeze the service: `python -m PyInstaller --onefile agy_service.py`
2. Open an **Elevated (Admin) PowerShell**.
3. Run `.\install_service.ps1`
   - This script creates `C:\ProgramData\AGYVerifier`.
   - It **discards any tainted pre-boundary keys**, forcing the SYSTEM process to generate a new trusted key.
   - It strips permissions and assigns Full Control *only* to `SYSTEM` and `Administrators`.
   - It copies the compiled `agy_service.exe` into the protected directory to prevent script/runtime tampering.
   - It registers a Scheduled Task to run the backend service as `NT AUTHORITY\SYSTEM` on startup.

## Viewing the Ledger
Run `python agy_gui.py` to launch a local desktop application that reads the protected ledger via a read-only RPC endpoint and displays all generated cryptographic certificates and their signatures.
I deliberately passed the verifier failing scenarios to ensure it correctly denies certificates:
- **Fake endpoint**: Rejected with a `FAIL` status and the `Max retries exceeded` request error.
- **Uninitialized Git Repo**: Rejected the `pushed` claim with a `FAIL` because it failed to fetch the remote origin.
- **Fake PID**: Rejected the `running` claim with a `FAIL` and "Process with PID 99999 does not exist".

All results correctly exited with status 1 and appended to the `agy_verification_audit.jsonl` audit log.
