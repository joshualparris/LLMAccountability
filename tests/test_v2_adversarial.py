import pytest
from v2.parsers.claim_extractor import ClaimExtractor
from v2.policy.engine import PolicyEngine
from v2.recipes.base import Verdict, RecipeResult

def test_extract_claims():
    report = "The automated tests passed, and I have pushed to main. The code is fully complete."
    claims = ClaimExtractor.extract(report)
    
    types = [c["type"] for c in claims]
    assert "tests-pass" in types
    assert "pushed" in types
    assert "fully-complete" in types

def test_policy_failure_dominates():
    claims = [{"id": "1", "type": "tests-pass", "raw_text": "tests pass"}]
    results = {"1": RecipeResult(Verdict.FAIL, {})}
    
    report = PolicyEngine.evaluate(claims, results)
    assert report["final_verdict"] == Verdict.FAIL

def test_policy_inconclusive_prevents_fully_complete():
    claims = [
        {"id": "1", "type": "tests-pass", "raw_text": "tests pass"},
        {"id": "2", "type": "fully-complete", "raw_text": "fully complete"}
    ]
    
    # Tests pass, but something else might be INCONCLUSIVE, or in this case we have an INCONCLUSIVE explicitly
    results = {
        "1": RecipeResult(Verdict.PASS, {}),
        "2": RecipeResult(Verdict.INCONCLUSIVE, {}) 
        # Actually, "fully-complete" is evaluated based on the presence of INCONCLUSIVE/FAIL elsewhere.
    }
    
    # Let's mock a case where a third claim is inconclusive
    claims.append({"id": "3", "type": "no-secrets", "raw_text": "secure"})
    results["3"] = RecipeResult(Verdict.INCONCLUSIVE, {})
    
    report = PolicyEngine.evaluate(claims, results)
    
    # The final verdict should be FAIL because an invalid claim ("fully-complete") was made and denied
    assert report["final_verdict"] == Verdict.FAIL
    
    # The fully-complete claim should be DENIED because of the inconclusive claim elsewhere
    denied_types = [c["type"] for c in report["denied_claims"]]
    assert "fully-complete" in denied_types

def test_policy_partial_maps_to_inconclusive():
    claims = [{"id": "1", "type": "no-secrets", "raw_text": "secure"}]
    results = {"1": RecipeResult(Verdict.PARTIAL, {})}
    
    report = PolicyEngine.evaluate(claims, results)
    assert report["final_verdict"] == Verdict.INCONCLUSIVE
    inconclusive_types = [c["type"] for c in report["inconclusive_claims"]]
    assert "no-secrets" in inconclusive_types
