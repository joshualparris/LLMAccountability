# Threat Model

LLMAccountability is designed to reduce trust in an AI coding agent's own completion report. Its core principle is that an agent should not be able to turn prose such as “tests pass” or “I pushed it” into authoritative success without independently gathered evidence.

This document describes the current implementation, not an aspirational security boundary.

## Assets to protect

- Ed25519 notary private key
- HMAC worker secret
- protected certification ledger
- runner credentials
- protected Python runtime and verification tooling
- integrity of structured verification evidence
- integrity of the policy result and signed V2 envelope

## Trust levels

### Trusted for the current design

- Windows host security boundary and ACL enforcement
- `NT AUTHORITY\SYSTEM` notary process
- installed notary code and signing key
- restricted worker process/code
- protected runtime installed by the administrator
- cryptographic primitives provided by the configured Python libraries

### Untrusted or potentially misleading

- AI agent completion prose
- audited Markdown report
- repository under test
- tests contained in the repository
- stdout/stderr produced by untrusted commands
- caller-supplied V2 claim list/context/subject metadata until independently checked
- network and remote-service availability

### Reduced-trust execution identity

`AGYRunner` is used to execute verification commands without granting the untrusted repository direct access to the SYSTEM notary identity or signing key.

## Threats addressed

### Agent self-certification

An agent cannot create a V2 PASS simply by writing “tests passed”. Supported claims require recipe execution and authenticated evidence before policy evaluation.

### Caller-provided verdict signing

`/v2/attest` does not accept caller-provided recipe verdicts. The notary chooses and executes the current recipes itself before signing the returned envelope.

### Forged worker evidence

Worker evidence is HMAC-authenticated with the worker secret. The notary rejects missing or invalid signatures.

### Ledger record editing

The `/certify` ledger is hash-chained and Ed25519-signed. Before accepting a new `/certify` action, the service validates previous hashes, certificate IDs, and signatures. Modification or corruption of an existing record is intended to make validation fail closed.

### False test success from a bare exit code

The `python-full` certification path requires structured pytest metrics, non-zero collection, consistent counts, workspace fingerprinting, protected-runtime identity/hash information, and a known pytest version in addition to exit code 0.

### False Git push claims

The Git verification path gathers local and remote state and requires usable SHAs and remote lookup evidence. Prerequisite/network failures do not become success.

### Credential leakage in diagnostic snippets

The worker sanitises several common credential forms and the runner password before truncating diagnostic output. This reduces accidental leakage but is not a general-purpose secret scanner.

## Threats only partially addressed

### Malicious or weak tests

LLMAccountability can establish that the configured tests ran and passed under the verified execution path. It does not prove that those tests adequately cover the intended requirement or that the tests themselves are honest.

### Repository-controlled tooling

The protected Python executable reduces one source of runtime substitution, but repository code and test code remain untrusted inputs. Stronger hermetic/sandboxed build and dependency controls are outside the current implementation.

### Remote Git meaning

A matching remote SHA establishes the observed Git relationship at verification time. It does not prove code review quality, deployment success, branch-protection compliance, or that the remote host itself is uncompromised.

### Host-local credential storage

The worker reads the `AGYRunner` password from a protected file and passes it to a PowerShell child via an environment variable. The design relies on Windows ACL/process isolation and does not claim resistance to an administrator or SYSTEM-level attacker inspecting protected state or process memory.

## Out of scope / not currently defended

### Administrator or SYSTEM compromise

An attacker with effective administrator/SYSTEM control can undermine the local trust boundary, replace binaries, access protected secrets, alter runtime state, or interfere with the notary. The current design is not a hardware-backed or remotely anchored trust system.

### Signing-key theft

The Ed25519 key is host-local. There is no TPM/HSM-backed key custody in the current implementation.

### External transparency anchoring

The protected certification ledger is local. There is no external append-only transparency service that would detect a privileged attacker replacing the entire local history together with the local key/state.

### Arbitrary semantic correctness

The system cannot prove that software meets every unstated human intention. It verifies implemented claim recipes and policy conditions.

### General security review

Although the V2 extractor recognises `security-reviewed`, there is no dedicated security-review recipe. Such a claim is currently `INCONCLUSIVE`.

### Proof that no secrets were committed

Although `no-secrets` wording can be extracted, V2 does not currently implement a repository secret-scanning recipe for it. Diagnostic redaction is not equivalent to proving repository cleanliness.

## V2 attestation limitations

### Report subject is not yet strongly bound by the CLI

`agy.py` currently sends the literal placeholder `sha256:dummy` as `subject_digest` when it calls `/v2/attest`.

The notary also accepts the caller-supplied `subject_name` and `subject_digest`; it does not independently read and hash the report file.

Therefore the current DSSE signature authenticates the envelope produced by the notary, but the in-toto subject digest **does not yet provide a trustworthy cryptographic binding to the exact audited Markdown report contents**.

Do not describe current V2 attestations as content-addressed proof of a specific report until the subject digest is independently computed/validated.

### V2 attestations are not appended to the `/certify` ledger

The current `/v2/attest` path signs and returns a DSSE envelope directly. It does not append that envelope to `protected_ledger.jsonl`, and it does not call the `/certify` ledger-validation path first.

The signed envelope can still be cryptographically verified with the notary public key, but persistence/ordering/tamper history for V2 attestations is not currently provided by the v1 certification ledger.

### No-claim default

If no recognised claims are extracted, the current policy engine can return PASS because there are no failed/inconclusive claims. That should be interpreted as “nothing checkable was evaluated”, not “the report is verified”.

## Security invariants worth preserving

Future changes should preserve these properties:

1. The audited agent does not hold the notary signing key.
2. The notary does not sign caller-supplied verdicts without independent evaluation.
3. Missing or malformed evidence never silently becomes PASS.
4. Unsupported claim types remain explicitly inconclusive.
5. Worker evidence authentication is checked before it is trusted.
6. Broad completion claims cannot override narrower failed/inconclusive evidence.
7. Diagnostics should not persist raw known credentials.
8. A stronger claim must require at least as strong evidence as the narrower claims it subsumes.

## Deployment caution

The Windows installer creates identities, changes ACLs/logon rights, and installs protected runtime/service state. Review `install_service.ps1` and perform physical Windows validation when changing the boundary. Unit tests alone do not validate the complete OS security configuration.
