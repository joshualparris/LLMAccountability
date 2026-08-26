# Antigravity Accountability Framework

The framework has been completely rewritten into an independent Certification Authority to physically prevent Antigravity from confabulating success.

## What was built
1. **The Certification Authority CLI (`agy_verifier.py`)**: A Python script using standard `argparse` that acts as the sole source of observed evidence. It accepts claims and validates them structurally.
2. **The Enforcement Rule (`strict_verification.md`)**: An `always_on` Antigravity rule instructing the model that it is structurally forbidden from claiming success without obtaining a Certificate ID from the CLI first.
3. **Audit Trail**: Every certification attempt is recorded in `agy_verification_audit.jsonl`.

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

## Testing Performed
I deliberately passed the verifier failing scenarios to ensure it correctly denies certificates:
- **Fake endpoint**: Rejected with a `FAIL` status and the `Max retries exceeded` request error.
- **Uninitialized Git Repo**: Rejected the `pushed` claim with a `FAIL` because it failed to fetch the remote origin.
- **Fake PID**: Rejected the `running` claim with a `FAIL` and "Process with PID 99999 does not exist".

All results correctly exited with status 1 and appended to the `agy_verification_audit.jsonl` audit log.
