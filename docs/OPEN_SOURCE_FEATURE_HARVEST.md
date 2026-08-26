# Open Source Feature Harvest

This document records the upstream open-source concepts and mechanisms we are adapting for v2 of LLMAccountability. We deliberately do not vendor entire codebases, but rather integrate the best architectural principles and abstractions from the agent-safety ecosystem.

## 1. Orthogon-AI-Labs/agent-verify
*   **Repository/Commit:** `Orthogon-AI-Labs/agent-verify` (latest)
*   **Licence:** MIT
*   **Feature to Adopt:** Final-answer claim extraction (parsing the agent's proposed final report to identify specific verifiable claims), automated fallback verification (PASS / FAIL / INCONCLUSIVE), secret scanning, and forcing correction of unsupported wording.
*   **Action:** ADAPT
*   **Why:** We want our v2 CLI (`agy audit-report`) to automatically ingest a proposed markdown report, break it down into granular claims, map those to verifier recipes, and prevent the final report from reaching the user if unsupported claims exist.

## 2. lordaeternus/agent-execution-harness
*   **Repository/Commit:** `lordaeternus/agent-execution-harness` (latest)
*   **Licence:** MIT
*   **Feature to Adopt:** Task contracts, required-evidence inference, gating requirements, and the explicit distinction between agent confidence and evidence-backed verified claims.
*   **Action:** REIMPLEMENT
*   **Why:** Reimplementing these concepts in Python fits our CLI structure perfectly. It allows `agy check-work` and `agy finish --check` to block completion until the exact mandatory evidence thresholds (artifacts, SHA-256 hashes, test coverage) are met.

## 3. AndreaGriffiths11/proof-agent
*   **Repository/Commit:** `AndreaGriffiths11/proof-agent` (latest)
*   **Licence:** MIT
*   **Feature to Adopt:** Separate adversarial reviewer model for semantic claims, requiring explicit file/line evidence for PR blocking. PASS / FAIL / PARTIAL verdict mapping.
*   **Action:** ADAPT
*   **Why:** Deterministic checks can verify if tests pass, but they cannot verify if "all requirements were met." By forcing semantic claims to be independently audited by a separate (non-worker) adversarial prompt equipped with the evidence, we close the semantic inflation loophole.

## 4. NousResearch/hermes-agent verification system
*   **Repository/Commit:** `NousResearch/hermes-agent` (latest)
*   **Licence:** MIT
*   **Feature to Adopt:** Lifecycle verification recipes and hooks.
*   **Action:** REIMPLEMENT
*   **Why:** Moving away from hardcoded logic in `agy_service.py` to a pluggable recipe system allows us to easily support arbitrary checks (e.g., specific linters, deployment validations) triggered at correct points in the agent lifecycle.

## 5. Sigstore/cosign + in-toto
*   **Repository/Commit:** `sigstore/cosign`, `in-toto/in-toto` (latest)
*   **Licence:** Apache-2.0
*   **Feature to Adopt:** Standardized DSSE (Dead Simple Signing Envelope) and in-toto attestation structures. Subjects identified by digests, structured predicate mapping.
*   **Action:** ADAPT
*   **Why:** Rather than inventing our own proprietary JSON certificate schema, generating standard in-toto/SLSA envelopes signed by our existing Ed25519 notary provides ecosystem compatibility and cryptographic non-repudiation.

## 6. SLSA Provenance Specifications
*   **Repository/Commit:** `slsa-framework/slsa` (latest)
*   **Licence:** Apache-2.0 (Specification)
*   **Feature to Adopt:** Provenance vocabulary (materials, builder, process, subject).
*   **Action:** REIMPLEMENT (Vocabulary usage)
*   **Why:** Adopting the standard SLSA terminology ensures our verification receipts are widely understood and semantically correct when identifying *what* was built and *how*.

## 7. Open Policy Agent (OPA)
*   **Repository/Commit:** `open-policy-agent/OPA` (latest)
*   **Licence:** Apache-2.0
*   **Feature to Adopt:** Policy-as-code separation (decoupling evidence collection from the decision logic).
*   **Action:** REIMPLEMENT (Conceptually)
*   **Why:** Hardcoding "tests-pass == completion" is too brittle. By abstracting the evaluation into a policy layer (whether Rego or a Python equivalent), we can enforce complex gating (e.g., `FAIL dominates`, `INCONCLUSIVE prevents 'fully complete' claim`).
