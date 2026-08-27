import os
import json
import base64
import hashlib
import hmac
import subprocess
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import uvicorn

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

PROTECTED_DIR = "C:/ProgramData/AGYVerifier"
os.makedirs(PROTECTED_DIR, exist_ok=True)
KEY_PATH = os.path.join(PROTECTED_DIR, "private.pem")
PUB_KEY_PATH = os.path.join(PROTECTED_DIR, "public.pem")
LEDGER_PATH = os.path.join(PROTECTED_DIR, "protected_ledger.jsonl")
SECRET_PATH = os.path.join(PROTECTED_DIR, "worker_secret.key")
WORKER_URL = "http://127.0.0.1:8124/execute"

# Ensure keys exist
try:
    if not os.path.exists(KEY_PATH):
        private_key = ed25519.Ed25519PrivateKey.generate()
        with open(KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(PUB_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open(KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
except Exception:
    private_key = None

app = FastAPI(title="Antigravity Protected Verification Service")

def get_secret():
    if not os.path.exists(SECRET_PATH):
        # Generate on first run if missing
        secret = os.urandom(32)
        with open(SECRET_PATH, "wb") as f:
            f.write(secret)
    with open(SECRET_PATH, "rb") as f:
        return f.read().strip()

def verify_worker_signature(evidence: dict, signature: str) -> bool:
    canonical = json.dumps(evidence, sort_keys=True).encode("utf-8")
    expected = hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

class ClaimRequest(BaseModel):
    claim: str
    repo_path: str = "."
    profile: Optional[str] = None
    pid: Optional[int] = None
    expected_bin_hash: Optional[str] = None
    url: Optional[str] = None
    expected_status: int = 200
    expected_content: Optional[str] = None

def validate_ledger():
    if not os.path.exists(LEDGER_PATH):
        return
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if not lines:
        return
        
    prev_hash = "0" * 64
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise RuntimeError(f"Audit log corrupt at line {i+1}")
            
        expected_hash = record.get("hash")
        if record.get("previous_hash") != prev_hash:
            raise RuntimeError(f"previous_hash mismatch at line {i+1}")
            
        temp_record = {
            "timestamp": record["timestamp"],
            "claim": record["claim"],
            "status": record["status"],
            "evidence": record["evidence"],
            "previous_hash": prev_hash
        }
        if "error" in record:
            temp_record["error"] = record["error"]
            
        canonical_json = json.dumps(temp_record, sort_keys=True)
        calculated_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
        
        if calculated_hash != expected_hash:
            raise RuntimeError(f"Ledger tampered or corrupted at line {i+1}!")
            
        # Reconstruct expected cert ID
        try:
            ts = datetime.fromisoformat(record["timestamp"])
            expected_cert_id = f"AGY-{ts.strftime('%Y%m%d')}-{calculated_hash[:8]}"
            if record.get("certificate_id") != expected_cert_id:
                raise RuntimeError(f"certificate_id mismatch at line {i+1}")
        except ValueError:
            raise RuntimeError(f"Invalid timestamp format at line {i+1}")
            
        # Verify Ed25519 Signature
        sig_b64 = record.get("signature_ed25519")
        if not sig_b64:
            raise RuntimeError(f"Missing signature at line {i+1}")
        try:
            sig_bytes = base64.b64decode(sig_b64)
            canonical_record_for_sig = dict(record)
            del canonical_record_for_sig["signature_ed25519"]
            
            with open(PUB_KEY_PATH, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
                
            pub_key.verify(
                sig_bytes,
                json.dumps(canonical_record_for_sig, sort_keys=True).encode("utf-8")
            )
        except Exception:
            raise RuntimeError(f"Invalid cryptographic signature at line {i+1}")
            
        prev_hash = expected_hash

def get_last_hash() -> str:
    if not os.path.exists(LEDGER_PATH):
        return "0" * 64
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                return "0" * 64
            return json.loads(lines[-1])["hash"]
    except Exception as e:
        raise RuntimeError(f"Audit log is corrupt or unreadable: {e}")

def append_ledger(record: dict):
    with open(LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def sign_record(record: dict) -> str:
    canonical_json = json.dumps(record, sort_keys=True).encode("utf-8")
    signature = private_key.sign(canonical_json)
    return base64.b64encode(signature).decode("utf-8")

@app.get("/ledger")
def get_ledger():
    if not os.path.exists(LEDGER_PATH):
        return []
    records = []
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records

@app.post("/certify")
def certify(req: ClaimRequest):
    # Enforce fail-closed ledger validation before taking any action
    try:
        validate_ledger()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    status = "UNKNOWN"
    error = None
    evidence = {}

    try:
        # Request execution from unprivileged worker
        payload = req.dict(exclude_none=True)
        resp = requests.post(WORKER_URL, json=payload, timeout=30)
        
        if resp.status_code != 200:
            raise ValueError(f"Worker execution failed: {resp.text}")
            
        worker_resp = resp.json()
        evidence = worker_resp.get("evidence", {})
        sig = worker_resp.get("signature")
        
        if not sig or not verify_worker_signature(evidence, sig):
            raise ValueError("Worker evidence signature is missing or invalid. Potential forgery detected.")
            
        if "error" in evidence:
            raise ValueError(f"Worker encountered error: {evidence['error']}")

        class AttrDict(dict):
            def __init__(self, *args, **kwargs):
                super(AttrDict, self).__init__(*args, **kwargs)
                self.__dict__ = self
        ev = AttrDict(evidence)

        if req.claim == "pushed":
            git_remote_url = ev.get("git_remote_url", {})
            git_status = ev.get("git_status", {})
            local_head = ev.get("git_rev_parse_head", {}).get("stdout_snippet", "").strip()
            ls_remote = ev.get("git_ls_remote", {}).get("stdout_snippet", "").strip()
            remote_sha = ls_remote.split()[0] if ls_remote else ""
            
            remote_lookup_succeeded = git_remote_url.get("exit_code") == 0 and ev.get("git_ls_remote", {}).get("exit_code") == 0
            worktree_clean = git_status.get("exit_code") == 0 and git_status.get("stdout_snippet", "").strip() == ""
            local_branch = ev.get("local_branch", "unknown")
            remote_url = git_remote_url.get("stdout_snippet", "").strip()
            
            if not remote_lookup_succeeded: raise ValueError("Failed to lookup remote origin")
            if not local_head: raise ValueError("Could not get local HEAD")
            if not remote_sha: raise ValueError("Could not get remote HEAD")
            if local_head != remote_sha: raise ValueError(f"Local HEAD {local_head} does not match remote {remote_sha}")
            
            evidence = {
                "remote_lookup_succeeded": remote_lookup_succeeded,
                "worktree_clean": worktree_clean,
                "local_head": local_head,
                "local_branch": local_branch,
                "remote_head": remote_sha,
                "remote_url": remote_url,
                "git_remote_url": git_remote_url,
                "git_ls_remote": ev.get("git_ls_remote")
            }
            status = "PASS"

        elif req.claim == "tests-pass":
            exit_code = ev.get("exit_code")
            if exit_code != 0:
                raise ValueError(f"Tests failed with exit code {exit_code}")
                
            collected = ev.get("tests")
            passed = ev.get("passed")
            failures = ev.get("failures")
            errors = ev.get("errors")
            skipped = ev.get("skipped")
            
            if req.profile == "python-full":
                if ev.get("diagnostic_reason"):
                    raise ValueError(f"Diagnostic reason present: {ev.get('diagnostic_reason')}")
                if not ev.get("workspace_fingerprint"):
                    raise ValueError("Missing or empty workspace_fingerprint")
                if ev.get("workspace_file_count") is None or ev.get("workspace_file_count") < 0:
                    raise ValueError("Invalid workspace_file_count")
                if collected is None or passed is None or failures is None or errors is None or skipped is None:
                    raise ValueError("Missing required test metrics")
                if failures != 0 or errors != 0:
                    raise ValueError(f"Test failures or errors present: failures={failures}, errors={errors}")
                if passed + failures + errors + skipped != collected:
                    raise ValueError("Inconsistent test metrics sum")
                
                if ev.get("python_executable") != "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe":
                    raise ValueError(f"Protected runtime not used: {ev.get('python_executable')}")
                if not ev.get("python_executable_sha256"):
                    raise ValueError("Missing python_executable_sha256")
                pytest_version = ev.get("pytest_version")
                if not pytest_version or pytest_version == "unknown":
                    raise ValueError("Invalid or unknown pytest_version")
            else:
                # Fallback for other profiles
                if collected is not None and failures is not None and passed is not None and skipped is not None:
                    if failures > 0 or (errors is not None and errors > 0):
                        raise ValueError(f"Inconsistent evidence: exit_code is 0 but there are failures ({failures}) or errors ({errors})")
                    if collected < 0 or passed < 0 or failures < 0 or skipped < 0:
                        raise ValueError("Inconsistent evidence: negative test metric counts")
                    if passed + failures + skipped > collected:
                        raise ValueError("Inconsistent evidence: passed + failures + skipped > collected")
                    
            status = "PASS"

        elif req.claim == "running":
            if ev.get("actual_bin_hash") != req.expected_bin_hash:
                raise ValueError("Binary hash mismatch")
            status = "PASS"

        elif req.claim == "endpoint-working":
            if ev.get("actual_status") != req.expected_status:
                raise ValueError(f"Status {ev.get('actual_status')} != {req.expected_status}")
            if not ev.get("content_found"):
                raise ValueError("Expected content not found in response")
            status = "PASS"

        else:
            raise ValueError(f"Unsupported claim type: {req.claim}")

    except Exception as e:
        status = "FAIL"
        error = str(e)

    prev_hash = get_last_hash()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "claim": req.claim,
        "status": status,
        "evidence": evidence,
        "previous_hash": prev_hash
    }
    if error:
        record["error"] = error
        
    canonical_json = json.dumps(record, sort_keys=True)
    new_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
    
    record["hash"] = new_hash
    cert_id = f"AGY-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{new_hash[:8]}"
    record["certificate_id"] = cert_id
    
    record["signature_ed25519"] = sign_record(record)
    append_ledger(record)
    return record

def pae(payload_type: str, payload: str) -> bytes:
    # DSSE Pre-Authentication Encoding (PAE)
    # PAE(type, payload) = "DSSEv1" + " " + len(type) + " " + type + " " + len(payload) + " " + payload
    
    # payload_type and payload are expected to be strings (payload is base64 string typically, but PAE operates on raw bytes of the strings)
    type_bytes = payload_type.encode('utf-8')
    payload_bytes = payload.encode('utf-8')
    
    pae_str = b"DSSEv1 " + str(len(type_bytes)).encode('utf-8') + b" " + type_bytes + b" " + str(len(payload_bytes)).encode('utf-8') + b" " + payload_bytes
    return pae_str

class V2ExecuteRequest(BaseModel):
    claim: str
    repo_path: str = "."
    profile: Optional[str] = None

class V2SignRequest(BaseModel):
    payloadType: str
    payload: str

@app.post("/v2/execute")
def v2_execute(req: V2ExecuteRequest):
    # Route to worker
    resp = requests.post(WORKER_URL, json=req.dict(), timeout=30)
    if resp.status_code != 200:
        raise HTTPException(status_code=500, detail="Worker execution failed")
        
    worker_resp = resp.json()
    evidence = worker_resp.get("evidence", {})
    sig = worker_resp.get("signature")
    
    if not sig or not verify_worker_signature(evidence, sig):
        raise HTTPException(status_code=403, detail="Worker signature invalid or missing")
        
    return {"evidence": evidence, "authenticated": True}

from v2.policy.engine import PolicyEngine
from v2.recipes.base import Verdict, RecipeResult
from v2.attestations.intoto import InTotoAttestation

class V2AttestRequest(BaseModel):
    claims: list
    context: dict
    subject_name: str
    subject_digest: str

@app.post("/v2/attest")
def v2_attest(req: V2AttestRequest):
    # To prevent acting as a signing oracle, the Notary MUST independently
    # execute recipes, authenticate evidence, and evaluate policy.
    
    # We must import the recipes here to avoid circular dependencies if imported at top-level
    from v2.recipes.git import GitPushRecipe
    from v2.recipes.tests import TestsPassRecipe
    
    results = {}
    for c in req.claims:
        if c["type"] == "pushed":
            results[c["id"]] = GitPushRecipe().verify(c, req.context)
        elif c["type"] == "tests-pass":
            results[c["id"]] = TestsPassRecipe().verify(c, req.context)
        else:
            results[c["id"]] = RecipeResult(Verdict.INCONCLUSIVE, {}, "Recipe not implemented yet")
            
    report = PolicyEngine.evaluate(req.claims, results)
    
    # Generate the unsigned in-toto statement
    env = InTotoAttestation.create(
        subject_name=req.subject_name,
        subject_digest=req.subject_digest,
        claims=req.claims,
        results=results,
        policy_report=report
    )
    
    # Generate true DSSE signature
    encoded_pae = pae(env["payloadType"], env["payload"])
    signature = private_key.sign(encoded_pae)
    env["signatures"].append({
        "keyid": "agy-ed25519-notary",
        "sig": base64.b64encode(signature).decode("utf-8")
    })
    
    return env

if __name__ == "__main__":
    print(f"Starting Antigravity Protected Service (v1.5) on localhost:8123...")
    uvicorn.run(app, host="127.0.0.1", port=8123, log_level="warning")
