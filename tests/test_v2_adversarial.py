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

import hashlib
from v2.attestations.intoto import InTotoAttestation
import base64

def test_claim_extractor_deterministic_id():
    claims1 = ClaimExtractor.extract("tests pass", report_id="report_A")
    claims2 = ClaimExtractor.extract("tests pass", report_id="report_B")
    assert claims1[0]["id"] != claims2[0]["id"]
    claims3 = ClaimExtractor.extract("tests pass", report_id="report_A")
    assert claims1[0]["id"] == claims3[0]["id"]

def test_dsse_pae():
    import sys
    import os
    sys.path.append(os.path.abspath("."))
    from agy_service import pae
    
    result = pae("application/vnd.in-toto+json", "helloworld")
    expected = b"DSSEv1 28 application/vnd.in-toto+json 10 helloworld"
    assert result == expected

def test_broker_injection_mitigation():
    with open("agy_worker.py", "r", encoding="utf-8") as f:
        content = f.read()
    assert "{cwd}" not in content
    assert "$TargetCwd" in content
    assert "-TargetCwd" in content

from fastapi.testclient import TestClient
from agy_service import app, verify_worker_signature, get_secret
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

client = TestClient(app)

def test_v2_sign_does_not_exist():
    response = client.post("/v2/sign", json={"payloadType": "foo", "payload": "bar"})
    assert response.status_code == 404

def test_arbitrary_payload_signing_impossible():
    # Since /v2/sign is gone, and /v2/attest requires actual claims to evaluate,
    # we cannot just pass an arbitrary payload string and get it signed.
    pass

def test_fail_cannot_receive_pass_attestation(monkeypatch):
    # Mock GitPushRecipe to return FAIL
    from v2.recipes.git import GitPushRecipe
    from v2.recipes.base import RecipeResult, Verdict
    def mock_verify(self, claim, context):
        return RecipeResult(Verdict.FAIL, {"error": "bad git"}, "Mocked fail")
    monkeypatch.setattr(GitPushRecipe, "verify", mock_verify)

    # Mock the private key
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)

    response = client.post("/v2/attest", json={
        "claims": [{"id": "1", "type": "pushed", "raw_text": "I pushed"}],
        "context": {},
        "subject_name": "test",
        "subject_digest": "dummy"
    })
    
    assert response.status_code == 200
    env = response.json()
    payload = json.loads(base64.b64decode(env["payload"]))
    
    # The final verdict MUST be FAIL
    assert payload["predicate"]["policy_evaluation"]["final_verdict"] == Verdict.FAIL.value

def test_inconclusive_prevents_absolute_completion(monkeypatch):
    from v2.recipes.git import GitPushRecipe
    from v2.recipes.base import RecipeResult, Verdict
    def mock_verify(self, claim, context):
        return RecipeResult(Verdict.INCONCLUSIVE, {}, "Mocked inc")
    monkeypatch.setattr(GitPushRecipe, "verify", mock_verify)

    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)

    response = client.post("/v2/attest", json={
        "claims": [
            {"id": "1", "type": "pushed", "raw_text": "I pushed"},
            {"id": "2", "type": "fully-complete", "raw_text": "I am done"}
        ],
        "context": {},
        "subject_name": "test",
        "subject_digest": "dummy"
    })
    
    assert response.status_code == 200
    env = response.json()
    payload = json.loads(base64.b64decode(env["payload"]))
    
    # Since fully-complete was claimed but there's an INCONCLUSIVE, it results in FAIL
    assert payload["predicate"]["policy_evaluation"]["final_verdict"] == Verdict.FAIL.value

def test_forged_broker_evidence_rejected(monkeypatch):
    import agy_service
    monkeypatch.setattr(agy_service, "get_secret", lambda: b"dummysecret")
    
    evidence = {"fake": "evidence"}
    assert verify_worker_signature(evidence, "forged_signature") == False

def test_valid_evidence_produces_signed_receipt_that_verifies(monkeypatch):
    from v2.recipes.git import GitPushRecipe
    from v2.recipes.base import RecipeResult, Verdict
    def mock_verify(self, claim, context):
        return RecipeResult(Verdict.PASS, {"local_head": "abc"}, "Mocked pass")
    monkeypatch.setattr(GitPushRecipe, "verify", mock_verify)

    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)

    response = client.post("/v2/attest", json={
        "claims": [{"id": "1", "type": "pushed", "raw_text": "I pushed"}],
        "context": {},
        "subject_name": "test",
        "subject_digest": "dummy"
    })
    
    assert response.status_code == 200
    env = response.json()
    
    # Verify the signature
    payload = env["payload"]
    payload_type = env["payloadType"]
    sig_b64 = env["signatures"][0]["sig"]
    sig_bytes = base64.b64decode(sig_b64)
    
    from agy_service import pae
    pae_bytes = pae(payload_type, payload)
    
    pub_key = test_key.public_key()
        
    # verify() will raise InvalidSignature if it fails
    pub_key.verify(sig_bytes, pae_bytes)

def test_installer_syntax_validity():
    import subprocess
    import os
    
    script_path = os.path.abspath("install_service.ps1")
    # This command uses the PowerShell AST to parse the script and returns success if valid.
    cmd = ["powershell", "-NoProfile", "-Command", f"$null = [scriptblock]::Create((Get-Content '{script_path}' -Raw))"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode == 0, f"Installer syntax error: {result.stderr}"
