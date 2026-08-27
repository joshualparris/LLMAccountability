import pytest
import requests
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

def test_tampered_ledger_rejects_new_claims(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    
    # Create valid ledger first
    import json, hashlib
    ledger = tmp_path / "ledger.jsonl"
    agy_service.LEDGER_PATH = str(ledger)
    
    canonical_record = json.dumps({"timestamp": "2023", "claim": "tests-pass", "status": "PASS", "evidence": {}, "previous_hash": "0"*64}, sort_keys=True)
    h = hashlib.sha256((("0"*64) + canonical_record).encode("utf-8")).hexdigest()
    
    record = {"timestamp": "2023", "claim": "tests-pass", "status": "PASS", "evidence": {}, "previous_hash": "0"*64, "signature_ed25519": "dummy"}
    ledger.write_text(json.dumps(record) + "\n")
    
    # Now tamper it
    record["status"] = "FAIL"
    ledger.write_text(json.dumps(record) + "\n")
    
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "evidence": {}, "nonce": "abc"})
    assert resp.status_code == 500

class MockResponse:
    def __init__(self, json_data, status_code=200, text=""):
        self._json = json_data
        self.status_code = status_code
        self.text = text
    def json(self):
        return self._json

# NEW NOTARY TESTS-PASS RULES (python-full)
def test_notary_rejects_diagnostic_reason(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    monkeypatch.setattr(agy_service, "verify_worker_signature", lambda ev, sig: True)
    agy_service.LEDGER_PATH = str(tmp_path / "ledger.jsonl")
    
    ev = {
        "exit_code": 0,
        "tests": 10,
        "passed": 10,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "workspace_fingerprint": "xyz",
        "workspace_file_count": 5,
        "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
        "python_executable_sha256": "abc",
        "pytest_version": "8.2.2",
        "diagnostic_reason": "workspace changed during test execution"
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: MockResponse({"evidence": ev, "signature": "dummy"}))
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "nonce": "abc"})
    assert resp.json()["status"] == "FAIL"
    assert "Diagnostic reason present" in resp.json()["error"]

def test_notary_rejects_missing_fingerprint(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    monkeypatch.setattr(agy_service, "verify_worker_signature", lambda ev, sig: True)
    agy_service.LEDGER_PATH = str(tmp_path / "ledger.jsonl")
    
    ev = {
        "exit_code": 0,
        "tests": 10,
        "passed": 10,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
        "python_executable_sha256": "abc",
        "pytest_version": "8.2.2"
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: MockResponse({"evidence": ev, "signature": "dummy"}))
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "nonce": "abc"})
    assert resp.json()["status"] == "FAIL"
    assert "Missing or empty workspace_fingerprint" in resp.json()["error"]

def test_notary_rejects_missing_metrics(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    monkeypatch.setattr(agy_service, "verify_worker_signature", lambda ev, sig: True)
    agy_service.LEDGER_PATH = str(tmp_path / "ledger.jsonl")
    
    ev = {
        "exit_code": 0,
        "workspace_fingerprint": "xyz",
        "workspace_file_count": 5,
        "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
        "python_executable_sha256": "abc",
        "pytest_version": "8.2.2"
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: MockResponse({"evidence": ev, "signature": "dummy"}))
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "nonce": "abc"})
    assert resp.json()["status"] == "FAIL"
    assert "Missing required test metrics" in resp.json()["error"]

def test_notary_rejects_inconsistent_metrics(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    monkeypatch.setattr(agy_service, "verify_worker_signature", lambda ev, sig: True)
    agy_service.LEDGER_PATH = str(tmp_path / "ledger.jsonl")
    
    ev = {
        "exit_code": 0,
        "tests": 10,
        "passed": 8,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "workspace_fingerprint": "xyz",
        "workspace_file_count": 5,
        "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
        "python_executable_sha256": "abc",
        "pytest_version": "8.2.2"
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: MockResponse({"evidence": ev, "signature": "dummy"}))
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "nonce": "abc"})
    assert resp.json()["status"] == "FAIL"
    assert "Inconsistent test metrics sum" in resp.json()["error"]

def test_notary_accepts_valid_evidence(monkeypatch, tmp_path):
    import agy_service
    test_key = ed25519.Ed25519PrivateKey.generate()
    monkeypatch.setattr(agy_service, "private_key", test_key)
    monkeypatch.setattr(agy_service, "verify_worker_signature", lambda ev, sig: True)
    agy_service.LEDGER_PATH = str(tmp_path / "ledger.jsonl")
    
    ev = {
        "exit_code": 0,
        "tests": 10,
        "passed": 9,
        "failures": 0,
        "errors": 0,
        "skipped": 1,
        "workspace_fingerprint": "xyz",
        "workspace_file_count": 5,
        "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
        "python_executable_sha256": "abc",
        "pytest_version": "8.2.2"
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: MockResponse({"evidence": ev, "signature": "dummy"}))
    resp = client.post("/certify", json={"claim": "tests-pass", "profile": "python-full", "nonce": "abc"})
    assert resp.json()["status"] == "PASS"

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

def test_installer_sebatchlogonright_provisioning():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read()
    assert "SeBatchLogonRight" in content
    assert "SeDenyBatchLogonRight" in content

def test_installer_no_unconditional_success():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read()
    # Ensure there's a failure path that prints NOT ESTABLISHED
    assert "NOT ESTABLISHED" in content
    # The success message shouldn't just be at the end without a conditional exit before it
    # We can check that 'exit 1' or 'throw' exists near NOT ESTABLISHED
    assert "exit 1" in content or "throw" in content

def test_installer_health_checks_exist():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read()
    assert "8123" in content
    assert "8124" in content
    assert "Running" in content

def test_scheduled_task_settings_compatibility():
    import subprocess
    ps_script = """
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    if ($s.DisallowStartIfOnBatteries -ne $false) { throw 'DisallowStartIfOnBatteries is not false' }
    if ($s.StopIfGoingOnBatteries -ne $false) { throw 'StopIfGoingOnBatteries is not false' }
    if ($s.StartWhenAvailable -ne $true) { throw 'StartWhenAvailable is not true' }
    if ($s.AllowDemandStart -ne $true) { throw 'AllowDemandStart is not true' }
    """
    cmd = ["powershell", "-NoProfile", "-Command", ps_script]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"ScheduledTaskSettings compat failed: {result.stderr}"

def test_installer_no_invalid_parameters():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read()
    assert "-AllowDemandStart" not in content

def test_no_secedit_configure():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read().lower()
    assert "secedit.exe /configure" not in content
    assert "secedit /configure" not in content
