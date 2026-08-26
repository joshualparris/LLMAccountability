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

class ClaimEvidence(BaseModel):
    # Git
    fetched_remote: Optional[bool] = None
    working_tree_clean: Optional[bool] = None
    local_head: Optional[str] = None
    remote_head: Optional[str] = None
    ls_remote_sha: Optional[str] = None
    # Tests
    command: Optional[str] = None
    exit_code: Optional[int] = None
    # Process
    pid: Optional[int] = None
    executable_path: Optional[str] = None
    actual_bin_hash: Optional[str] = None
    expected_bin_hash: Optional[str] = None
    # Endpoint
    url: Optional[str] = None
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    expected_content: Optional[str] = None
    content_found: Optional[bool] = None

class ClaimRequest(BaseModel):
    claim: str
    evidence: ClaimEvidence

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
            
            # Re-read public key just for validation in case it's not loaded globally
            with open(PUB_KEY_PATH, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read(), password=None)
                
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

    try:
        ev = req.evidence
        if req.claim == "pushed":
            if not ev.fetched_remote: raise ValueError("Failed to fetch remote origin")
            if not ev.working_tree_clean: raise ValueError("Working tree is dirty")
            if ev.local_head != ev.remote_head: raise ValueError("Local head does not match remote head")
            if ev.local_head != ev.ls_remote_sha: raise ValueError("Local head does not match ls-remote SHA")
            status = "PASS"

        elif req.claim == "tests-pass":
            if ev.command not in ["python -m pytest", "npm test"]:
                raise ValueError("Unauthorized test command")
            if ev.exit_code != 0:
                raise ValueError(f"Tests failed with exit code {ev.exit_code}")
            status = "PASS"

        elif req.claim == "running":
            if not ev.expected_bin_hash:
                raise ValueError("Missing expected binary hash")
            if ev.actual_bin_hash != ev.expected_bin_hash:
                raise ValueError("Binary hash mismatch")
            status = "PASS"

        elif req.claim == "endpoint-working":
            if not ev.expected_content:
                raise ValueError("Missing expected content")
            if ev.actual_status != ev.expected_status:
                raise ValueError(f"Status {ev.actual_status} != {ev.expected_status}")
            if not ev.content_found:
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
        "evidence": req.evidence.dict(exclude_none=True),
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
