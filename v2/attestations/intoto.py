import json
import hashlib
from typing import Dict, Any

class InTotoAttestation:
    @staticmethod
    def create(subject_name: str, subject_digest: str, claims: list, results: dict, policy_report: dict) -> Dict[str, Any]:
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": subject_name,
                "digest": {"sha256": subject_digest}
            }],
            "predicateType": "https://llmaccountability.local/verification/v1",
            "predicate": {
                "claims": claims,
                "results": {k: {"verdict": v.verdict.value, "evidence": v.evidence} for k, v in results.items()},
                "policy_evaluation": {
                    "final_verdict": policy_report["final_verdict"].value,
                    "allowed": [c["type"] for c in policy_report["allowed_claims"]],
                    "denied": [c["type"] for c in policy_report["denied_claims"]]
                }
            }
        }
