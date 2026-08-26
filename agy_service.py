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

def run_git(cmd: list, cwd: str) -> tuple[int, str]:
    try:
        res = subprocess.run(["git"] + cmd, cwd=cwd, capture_output=True, text=True, check=False)
        return res.returncode, res.stdout.strip()
    except Exception as e:
        return -1, str(e)

def get_file_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def sign_record(record: dict) -> str:
    # Sign the canonical JSON without the signature field itself
    canonical_json = json.dumps(record, sort_keys=True).encode("utf-8")
    signature = private_key.sign(canonical_json)
    return base64.b64encode(signature).decode("utf-8")

@app.post("/certify")
def certify(req: ClaimRequest):
    # Enforce fail-closed ledger validation before taking any action
    try:
        validate_ledger()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    evidence = {}
    status = "UNKNOWN"
    error = None

    try:
        if req.claim == "pushed":
            evidence["repo_path"] = os.path.abspath(req.repo_path)
            
            code, out = run_git(["fetch", "origin"], evidence["repo_path"])
            evidence["fetched_remote"] = (code == 0)
            if code != 0:
                raise ValueError("Failed to fetch remote origin")

            code, status_out = run_git(["status", "--porcelain"], evidence["repo_path"])
            evidence["working_tree_clean"] = (code == 0 and len(status_out) == 0)
            if not evidence["working_tree_clean"]:
                raise ValueError("Working tree is dirty")

            code, local_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], evidence["repo_path"])
            evidence["branch"] = local_branch

            code, local_sha = run_git(["rev-parse", "HEAD"], evidence["repo_path"])
            evidence["local_head"] = local_sha

            code, remote_sha = run_git(["rev-parse", "@{u}"], evidence["repo_path"])
            if code != 0:
                 raise ValueError("No upstream branch configured")
            evidence["remote_head"] = remote_sha

            # Independent ls-remote check
            code, ls_remote_out = run_git(["ls-remote", "origin", f"refs/heads/{local_branch}"], evidence["repo_path"])
            if code != 0 or not ls_remote_out:
                raise ValueError("Failed to verify remote SHA via ls-remote")
            
            ls_remote_sha = ls_remote_out.split()[0]
            evidence["ls_remote_sha"] = ls_remote_sha

            if local_sha == remote_sha == ls_remote_sha:
                status = "PASS"
            else:
                raise ValueError(f"SHAs do not match: local={local_sha}, remote={remote_sha}, ls-remote={ls_remote_sha}")

        elif req.claim == "tests-pass":
            if not req.profile:
                raise ValueError("Missing --profile for tests-pass")
            
            # Map profiles to hardcoded, safe commands
            PROFILES = {
                "python-full": ["python", "-m", "pytest"],
                "npm-full": ["npm", "test"]
            }
            if req.profile not in PROFILES:
                raise ValueError(f"Unknown test profile '{req.profile}'. Allowed: {list(PROFILES.keys())}")
                
            cmd = PROFILES[req.profile]
            evidence["command"] = " ".join(cmd)
            evidence["repo_path"] = os.path.abspath(req.repo_path)
            
            code, local_sha = run_git(["rev-parse", "HEAD"], evidence["repo_path"])
            evidence["commit_sha"] = local_sha if code == 0 else "unknown"
            
            code, status_out = run_git(["status", "--porcelain"], evidence["repo_path"])
            evidence["dirty_working_tree"] = (code != 0 or len(status_out) > 0)

            # No shell=True!
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=evidence["repo_path"])
            evidence["exit_code"] = res.returncode
            evidence["stdout_snippet"] = res.stdout[:500]

            if res.returncode == 0:
                status = "PASS"
            else:
                raise ValueError(f"Tests failed with exit code {res.returncode}")

        elif req.claim == "running":
            if not req.pid:
                raise ValueError("Missing --pid")
            if not req.expected_bin_hash:
                raise ValueError("Missing --expected-bin-hash. Process identity verification is mandatory.")
            
            evidence["pid"] = req.pid
            
            if not psutil.pid_exists(req.pid):
                raise ValueError(f"Process with PID {req.pid} does not exist")
            
            proc = psutil.Process(req.pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                raise ValueError("Process is a zombie")

            try:
                exe_path = proc.exe()
                evidence["executable_path"] = exe_path
                
                actual_hash = get_file_sha256(exe_path)
                evidence["actual_bin_hash"] = actual_hash
                evidence["expected_bin_hash"] = req.expected_bin_hash
                
                if actual_hash != req.expected_bin_hash:
                    raise ValueError("Binary hash does not match expected hash (stale binary?)")

                evidence["start_time"] = datetime.fromtimestamp(proc.create_time(), timezone.utc).isoformat()
                evidence["command_line"] = proc.cmdline()
                status = "PASS"
                
            except psutil.AccessDenied:
                raise ValueError("Access denied reading process information")

        elif req.claim == "endpoint-working":
            if not req.url:
                raise ValueError("Missing --url")
            if not req.expected_content:
                raise ValueError("Missing --expected-content. Endpoint identity/content verification is mandatory.")
            
            evidence["url"] = req.url
            evidence["expected_status"] = req.expected_status
            evidence["expected_content"] = req.expected_content
            
            try:
                resp = requests.get(req.url, timeout=10)
                evidence["actual_status"] = resp.status_code
                
                if resp.status_code != req.expected_status:
                    raise ValueError(f"Status {resp.status_code} != {req.expected_status}")
                    
                evidence["content_snippet"] = resp.text[:500]
                if req.expected_content not in resp.text:
                    raise ValueError("Expected content not found in response")
                        
                status = "PASS"
            except requests.exceptions.RequestException as e:
                raise ValueError(f"Request failed: {str(e)}")

        else:
            raise ValueError(f"Unsupported claim type: {req.claim}")

    except Exception as e:
        status = "FAIL"
        error = str(e)

    # Generate record
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
    
    # Sign it with Ed25519
    record["signature_ed25519"] = sign_record(record)
    
    append_ledger(record)
    return record

if __name__ == "__main__":
    print(f"Starting Antigravity Protected Service (v1) on localhost:8123...")
    print(f"Ledger Path: {LEDGER_PATH}")
    print(f"Public Key Path: {PUB_KEY_PATH}")
    uvicorn.run(app, host="127.0.0.1", port=8123, log_level="warning")
