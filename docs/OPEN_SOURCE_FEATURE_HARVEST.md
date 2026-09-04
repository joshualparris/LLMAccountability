# Open Source Feature Harvest

This document records upstream open-source concepts that influenced LLMAccountability V2 and, importantly, their **current implementation status** in this repository.

LLMAccountability primarily reimplements or adapts architectural ideas rather than vendoring these projects. See `THIRD_PARTY_NOTICES.md` for attribution.

Status meanings:

- **IMPLEMENTED** — a concrete native implementation exists in the current default branch
- **PARTIAL** — part of the idea exists, but important pieces remain incomplete
- **PLANNED / NOT IMPLEMENTED** — recorded influence or intended direction, not a current capability

## 1. Orthogon-AI-Labs/agent-verify

- **Repository/Commit:** `Orthogon-AI-Labs/agent-verify` @ `b0212fd5c863f620e013f821d8234842adb8e8e3`
- **Licence:** MIT
- **Influence:** final-answer claim extraction, PASS/FAIL/INCONCLUSIVE semantics, unsupported-wording discipline, secret-scanning concepts
- **Current status:** **PARTIAL / IMPLEMENTED IN CORE AREAS**

Implemented natively:

- deterministic final-report claim extraction in `v2/parsers/claim_extractor.py`
- recipe verdicts and fail-closed aggregation
- CLI report auditing through `agy.py audit-report`
- unsupported recognised claims become `INCONCLUSIVE` rather than success

Not yet equivalent to the full intended feature set:

- `no-secrets` is recognised but has no dedicated V2 verification recipe
- `security-reviewed` is recognised but has no dedicated V2 verification recipe
- the extractor remains a small deterministic pattern set rather than broad semantic extraction

## 2. lordaeternus/agent-execution-harness

- **Repository/Commit:** `lordaeternus/agent-execution-harness` @ `401187291bf9e0cf5c91eaaedcf578912411b770`
- **Licence:** MIT
- **Influence:** task contracts, required-evidence inference, gating requirements, distinction between agent confidence and verified evidence
- **Current status:** **PARTIAL / PLANNED**

LLMAccountability V2 has a policy layer and explicit recipe/evidence gating, but it does **not** currently expose the previously proposed `agy check-work` or `agy finish --check` commands, nor a full native task-contract subsystem matching that earlier design note.

Do not treat those command names as current CLI features.

## 3. AndreaGriffiths11/proof-agent

- **Repository/Commit:** `AndreaGriffiths11/proof-agent` @ `184e2373a89c62745d91a4e7cda7d1dd5c324bf7`
- **Licence:** MIT
- **Influence:** adversarial semantic review, concrete evidence for semantic claims, PARTIAL-style verdict thinking
- **Current status:** **PLANNED / NOT IMPLEMENTED AS A SEPARATE REVIEWER**

The current V2 policy maps `PARTIAL` to `INCONCLUSIVE`, but there is no separate adversarial reviewer model in this repository that independently judges arbitrary semantic claims from file/line evidence.

Deterministic recipes currently cover only what they explicitly implement.

## 4. NousResearch/hermes-agent verification system

- **Repository/Commit:** `NousResearch/hermes-agent` @ `b742be711a15aad543a871d2d3022277b70dc551`
- **Licence:** MIT
- **Influence:** lifecycle verification recipes and hooks
- **Current status:** **PARTIAL**

Implemented:

- a recipe abstraction in `v2/recipes/base.py`
- concrete `tests-pass` and `pushed` recipes
- notary-side recipe dispatch for `/v2/attest`

Not yet implemented:

- a general plugin/registration system for arbitrary recipes
- broad lifecycle hooks across multiple coding-agent environments

Recipe dispatch remains explicit in `agy_service.py`.

## 5. Sigstore/cosign + in-toto

- **Repository/Commit:** `sigstore/cosign` @ `58aae9e112fa1de80594eed34667e920ac4d4a3b`; `in-toto/in-toto` @ `a8ce9ee2125ae5a4b041a4e37cc1cf10eed0da6b`
- **Licence:** Apache-2.0
- **Influence:** DSSE envelope structure, in-toto statement shape, subject digests, structured predicates
- **Current status:** **IMPLEMENTED WITH IMPORTANT LIMITATIONS**

Implemented natively:

- in-toto Statement v1-style payload in `v2/attestations/intoto.py`
- DSSE envelope
- DSSE PAE signing by the SYSTEM notary's Ed25519 key
- structured predicate containing claims, recipe results/evidence, and policy evaluation

Current limitation:

- `agy.py` currently supplies `sha256:dummy` as the subject digest, and the notary does not independently hash the report. The signed envelope is therefore **not yet a trustworthy content-addressed binding to the exact Markdown report**.

See `docs/THREAT_MODEL.md`.

## 6. SLSA provenance specifications

- **Repository/Commit:** `slsa-framework/slsa` @ `1686afeba11a456e470235ecf50cfc0d2f9ecbc3`
- **Licence:** Apache-2.0 (Specification)
- **Influence:** provenance vocabulary such as subject, materials, builder and process
- **Current status:** **PARTIAL / VOCABULARY INFLUENCE**

The current V2 attestation uses in-toto-style subject/predicate concepts but does not claim full SLSA provenance conformance or a specific SLSA build level.

## 7. Open Policy Agent (OPA)

- **Repository/Commit:** `open-policy-agent/OPA` @ `cfc343711c04bf7a735a80f440dc5fc20e696039`
- **Licence:** Apache-2.0
- **Influence:** separation of evidence collection from policy decision logic
- **Current status:** **IMPLEMENTED CONCEPTUALLY IN PYTHON**

`v2/policy/engine.py` is a separate deterministic policy layer. Current aggregate rules include:

- FAIL dominates the final verdict
- INCONCLUSIVE prevents a normal PASS
- PARTIAL is treated as INCONCLUSIVE
- a `fully-complete` claim is denied when any extracted claim is failed or inconclusive

LLMAccountability does **not** currently embed OPA/Rego; the architecture is an original Python implementation of the separation-of-concerns idea.

## Current implementation summary

| Capability | Status |
| --- | --- |
| Deterministic final-report claim extraction | Implemented |
| `tests-pass` V2 recipe | Implemented |
| `pushed` V2 recipe | Implemented |
| `no-secrets` V2 recipe | Not implemented |
| General `security-reviewed` recipe | Not implemented |
| Separate adversarial semantic reviewer | Not implemented |
| Python policy engine | Implemented |
| DSSE/in-toto-style signed envelope | Implemented |
| Trustworthy report subject digest binding | Not implemented yet |
| General pluggable recipe registry | Not implemented |
| Full SLSA conformance | Not claimed |

This table should be updated whenever implementation status changes so architectural inspiration is not mistaken for shipped capability.
