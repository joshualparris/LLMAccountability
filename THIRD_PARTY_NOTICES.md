# Third-Party Notices

LLMAccountability (v2) is a native implementation combining original anti-tampering enforcement with conceptual architectures derived from several prominent open-source projects in the AI safety and software supply chain space.

We gratefully acknowledge the following projects and their authors. While LLMAccountability primarily reimplements or adapts these concepts natively rather than directly vendoring source code, their architectural influence is central to this tool.

### agent-verify
*   **Source:** https://github.com/Orthogon-AI-Labs/agent-verify
*   **Licence:** MIT License
*   **Influence:** Final-answer claim extraction, JSON verification receipts, secret scanning principles, and the enforcement of PASS/FAIL/INCONCLUSIVE states over agent self-assessments.

### agent-execution-harness
*   **Source:** https://github.com/lordaeternus/agent-execution-harness
*   **Licence:** MIT License
*   **Influence:** Task contracts, required-evidence inference, execution gating, and decoupling final reports from agent confidence.

### Proof Agent
*   **Source:** https://github.com/AndreaGriffiths11/proof-agent (also GitHub Marketplace)
*   **Licence:** MIT License
*   **Influence:** The separation of adversarial review from the execution agent, mapping PARTIAL verdicts, and requiring concrete file/line evidence for semantic claims.

### Hermes Agent
*   **Source:** https://github.com/NousResearch/hermes-agent
*   **Licence:** MIT License
*   **Influence:** Lifecycle verification recipes and execution hooks.

### Sigstore & in-toto
*   **Source:** https://github.com/sigstore/cosign , https://github.com/in-toto/in-toto
*   **Licence:** Apache License 2.0
*   **Influence:** Standardized attestation envelopes (DSSE), subject digest identification, and non-repudiation concepts.

### Open Policy Agent (OPA)
*   **Source:** https://github.com/open-policy-agent/OPA
*   **Licence:** Apache License 2.0
*   **Influence:** The concept of Policy-as-Code, strictly separating evidence collection from evaluation and decision rules.

---

*Any direct source code integration from these projects in future updates will preserve their respective copyright headers directly within the source files.*
