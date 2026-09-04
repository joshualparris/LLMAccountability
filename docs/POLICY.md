# V2 Policy

`v2/policy/engine.py` turns per-claim recipe results into a report-level decision. The policy is intentionally conservative: missing or partial evidence is not upgraded to success.

## Output

The policy report contains:

- `allowed_claims`
- `denied_claims`
- `inconclusive_claims`
- `final_verdict`

The final verdict is one of:

- `PASS`
- `FAIL`
- `INCONCLUSIVE`

## Evaluation rules

### Missing result

If an extracted claim has no recipe result, the claim is placed in `inconclusive_claims` and contributes to an overall inconclusive state.

### `PARTIAL`

A recipe-level `PARTIAL` result is normalised to `INCONCLUSIVE` before policy categorisation.

### `FAIL`

A failed recipe result places the claim in `denied_claims` and makes the final report `FAIL`.

### `INCONCLUSIVE`

An inconclusive recipe result places the claim in `inconclusive_claims`. If there are no failures, the final report becomes `INCONCLUSIVE`.

### `PASS`

A passing recipe result is placed in `allowed_claims` unless a special aggregate rule applies.

## Special rule: `fully-complete`

Broad completion wording has a stronger aggregate rule.

If the report includes a `fully-complete` claim and **any** extracted claim is failed or inconclusive, the completeness claim is denied and the final report is forced to `FAIL`.

This rule applies to wording such as:

- “fully complete”
- “production ready”
- “every requirement is implemented”

The intent is to prevent broad success language when narrower claims still lack proof.

## Unsupported claims

The V2 notary currently implements verification recipes for:

- `tests-pass`
- `pushed`

Recognised claim types without a recipe are assigned `INCONCLUSIVE` by `/v2/attest` with the reason `Recipe not implemented yet`.

That means a report containing only unsupported checkable claims cannot legitimately be described as verified by V2.

## Enforcement mode

The CLI supports:

```powershell
python agy.py audit-report final-report.md --enforce
```

With `--enforce`, the process exits non-zero whenever the returned policy `final_verdict` is not `PASS`.

Without `--enforce`, the CLI prints the audit result but does not use a non-PASS policy verdict alone as a process stop gate.

## Important edge case: no extracted claims

The current policy engine starts from `PASS`. If `ClaimExtractor` finds **zero recognised claims**, there are no failed or inconclusive claims to change that default, so the policy result is currently `PASS`.

That result means “no recognised claims were evaluated”; it must **not** be interpreted as evidence that an arbitrary report is correct or verified.

Callers that require at least one checkable claim should enforce that condition before relying on the policy verdict. This is a current implementation limitation, not a security guarantee.

## Evidence semantics

Policy evaluates recipe verdicts; it does not itself gather evidence. Evidence trust comes from the recipe/notary path:

1. worker executes the required observation under the runner identity;
2. worker HMAC-authenticates the evidence;
3. notary validates worker authentication;
4. recipe checks evidence completeness/consistency and returns a verdict;
5. policy aggregates those verdicts.

A policy PASS is therefore only as strong as the implemented recipes, evidence fields, runtime trust boundary, and the claim coverage of the report.

## Non-goals

The current policy does not prove:

- that tests provide adequate behavioural coverage;
- that every human requirement was represented by an extracted claim;
- that unsupported security or secret-scanning claims are true;
- semantic correctness of arbitrary code;
- that a claim omitted from the report is false or true.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the wider trust assumptions and current limitations.
