# Claim Types

LLMAccountability V2 audits checkable statements in an agent's completion report. Claim extraction is deterministic and intentionally narrow; wording that is not recognised is not silently converted into a stronger claim.

## Verdicts

Recipes use four internal verdicts:

- `PASS` — the available recipe evidence supports the claim
- `FAIL` — the available evidence contradicts or fails the claim
- `INCONCLUSIVE` — the claim cannot be established from trustworthy evidence
- `PARTIAL` — treated as `INCONCLUSIVE` by the current policy engine

Missing recipe results are also treated as inconclusive.

## `tests-pass`

Recognised wording includes patterns such as:

- “tests pass”
- “all tests passed”
- “automated tests passed”

### Current verification

Implemented by `TestsPassRecipe`.

For `python-full`, the protected path checks more than the process exit code. The notary requires structured, consistent pytest metrics, at least one collected test, no failures/errors, a workspace fingerprint, the protected Python runtime path and hash, and a known pytest version.

A spawn failure, diagnostic failure, missing required evidence, zero collected tests, inconsistent metrics, or inaccessible notary/worker cannot become PASS.

## `pushed`

Recognised wording includes patterns such as:

- “pushed to …”
- “push to main”
- “pushed … to GitHub”

### Current verification

Implemented by `GitPushRecipe`.

The recipe establishes local and remote Git state through protected execution. It expects usable local HEAD, upstream/remote evidence, and a successful remote lookup. The established SHAs must agree for PASS.

Network, command, or prerequisite failures are `INCONCLUSIVE`; an established mismatch is `FAIL`.

## `no-secrets`

Recognised wording:

- “no secrets were committed”

### Current verification

No dedicated V2 recipe is implemented yet. The claim is therefore `INCONCLUSIVE` in `/v2/attest`.

This is deliberate: diagnostic redaction and secret-handling safeguards elsewhere in the runtime are not equivalent to proving that a repository contains no committed secrets.

## `security-reviewed`

Recognised wording includes broad security assertions such as:

- “secure”
- “authentication is secure”

### Current verification

No dedicated V2 recipe is implemented yet. The claim is `INCONCLUSIVE`.

A passing test suite or successful Git push is not sufficient evidence for a general security claim.

## `fully-complete`

Recognised wording includes:

- “fully complete”
- “production ready”
- “every requirement is implemented”

### Current verification

There is currently no standalone recipe that can prove arbitrary completeness. The claim is therefore normally `INCONCLUSIVE` at recipe level.

In addition, `PolicyEngine` gives completeness wording special treatment: if any extracted claim is failed or inconclusive, the `fully-complete` claim is denied and the overall result is forced to `FAIL`.

This prevents a broad completion statement from passing when narrower evidence is missing.

## Claim IDs

`ClaimExtractor` creates a deterministic 16-character claim ID from:

- report ID
- claim type
- matched text
- match index

This keeps IDs stable for the same report identity and matched wording without relying on random IDs.

## Extraction is not verification

A claim appearing in the extracted list only means the report contains recognised wording. It does **not** mean the claim is true.

The verification chain is:

`report text → extracted claim → recipe evidence → recipe verdict → policy verdict → signed attestation`

If a claim has no trustworthy recipe evidence, the correct current state is `INCONCLUSIVE`.
