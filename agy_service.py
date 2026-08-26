import os
import json
import hashlib
import subprocess
import psutil
import requests
from datetime import datetime, timezone
import base64
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Protected paths
PROTECTED_DIR = os.path.abspath("C:/ProgramData/AGYVerifier")
os.makedirs(PROTECTED_DIR, exist_ok=True)

LEDGER_PATH = os.path.join(PROTECTED_DIR, "protected_ledger.jsonl")
KEY_PATH = os.path.join(PROTECTED_DIR, "private.pem")
PUB_KEY_PATH = os.path.join(PROTECTED_DIR, "public.pem")

# Ensure keys exist
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

app = FastAPI(title="Antigravity Protected Verification Service")

SECRET_PATH = os.path.join(PROTECTED_DIR, "worker_secret.key")
WORKER_URL = "http://127.0.0.1:8124/execute"

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
            if not ev.get("fetched_remote"): raise ValueError("Failed to fetch remote origin")
            if not ev.get("working_tree_clean"): raise ValueError("Working tree is dirty")
            if ev.get("local_head") != ev.get("remote_head"): raise ValueError("Local head does not match remote head")
            if ev.get("local_head") != ev.get("ls_remote_sha"): raise ValueError("Local head does not match ls-remote SHA")
            status = "PASS"

        elif req.claim == "tests-pass":
            if ev.get("exit_code") != 0:
                raise ValueError(f"Tests failed with exit code {ev.get('exit_code')}")
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

if __name__ == "__main__":
    print(f"Starting Antigravity Protected Service (v1) on localhost:8123...")
    print(f"Ledger Path: {LEDGER_PATH}")
    print(f"Public Key Path: {PUB_KEY_PATH}")
    uvicorn.run(app, host="127.0.0.1", port=8123, log_level="warning")
