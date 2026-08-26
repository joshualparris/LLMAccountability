import json
import base64
from typing import Dict, Any

class InTotoAttestation:
    @staticmethod
    def create(subject_name: str, subject_digest: str, claims: list, results: dict, policy_report: dict, signature: str = "") -> Dict[str, Any]:
        # Generate the in-toto statement
        statement = {
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
        
        # Serialize and base64 encode the statement payload
        statement_json = json.dumps(statement, separators=(',', ':')).encode('utf-8')
        payload_b64 = base64.b64encode(statement_json).decode('utf-8')
        
        # Wrap in standard DSSE envelope
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload_b64,
            "signatures": []
        }
        
        # If a cryptographic signature was provided (e.g. from our SYSTEM notary), append it
        if signature:
            envelope["signatures"].append({
                "keyid": "agy-ed25519-notary",
                "sig": signature
            })
            
        return envelope
