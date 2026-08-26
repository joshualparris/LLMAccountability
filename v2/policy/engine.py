from typing import List, Dict, Any
from v2.recipes.base import Verdict

class PolicyEngine:
    @staticmethod
    def evaluate(claims: List[Dict[str, Any]], results: Dict[str, Any]) -> Dict[str, Any]:
        report = {
            "allowed_claims": [],
            "denied_claims": [],
            "inconclusive_claims": [],
            "final_verdict": Verdict.PASS
        }
        
        # Pass 1: Global state and basic mapping
        has_inconclusive = False
        has_fail = False
        
        for claim in claims:
            cid = claim["id"]
            if cid not in results:
                has_inconclusive = True
                continue
                
            verdict = results[cid].verdict
            if verdict == Verdict.PARTIAL:
                verdict = Verdict.INCONCLUSIVE
                
            if verdict == Verdict.FAIL:
                has_fail = True
            elif verdict == Verdict.INCONCLUSIVE:
                has_inconclusive = True

        # Pass 2: Aggregate rules and categorization
        for claim in claims:
            cid = claim["id"]
            if cid not in results:
                report["inconclusive_claims"].append(claim)
                continue
                
            verdict = results[cid].verdict
            if verdict == Verdict.PARTIAL:
                verdict = Verdict.INCONCLUSIVE
                
            if claim["type"] == "fully-complete" and (has_inconclusive or has_fail):
                report["denied_claims"].append(claim)
                has_fail = True # Denying 'fully complete' explicitly forces final fail
            elif verdict == Verdict.FAIL:
                report["denied_claims"].append(claim)
            elif verdict == Verdict.INCONCLUSIVE:
                report["inconclusive_claims"].append(claim)
            else:
                report["allowed_claims"].append(claim)

        if has_fail:
            report["final_verdict"] = Verdict.FAIL
        elif has_inconclusive:
            report["final_verdict"] = Verdict.INCONCLUSIVE
            
        return report
