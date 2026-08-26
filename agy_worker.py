import os
import subprocess
import psutil
import requests
import hashlib
import hmac
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

WORKER_PORT = 8124
SECRET_PATH = "C:/ProgramData/AGYVerifier/worker_secret.key"

app = FastAPI(title="Antigravity Verification Worker")

class ExecuteRequest(BaseModel):
    claim: str
    repo_path: str = "."
    profile: Optional[str] = None
    pid: Optional[int] = None
    expected_bin_hash: Optional[str] = None
    url: Optional[str] = None
    expected_status: int = 200
    expected_content: Optional[str] = None

def get_secret():
    with open(SECRET_PATH, "rb") as f:
        return f.read().strip()

def sign_response(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()

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

@app.post("/execute")
def execute(req: ExecuteRequest):
    evidence = {}
    try:
        if req.claim == "pushed":
            repo = os.path.abspath(req.repo_path)
            evidence["repo_path"] = repo
            code, _ = run_git(["fetch", "origin"], repo)
            evidence["fetched_remote"] = (code == 0)
            code, status_out = run_git(["status", "--porcelain"], repo)
            evidence["working_tree_clean"] = (code == 0 and len(status_out) == 0)
            code, local_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
            code, local_sha = run_git(["rev-parse", "HEAD"], repo)
            evidence["local_head"] = local_sha if code == 0 else "unknown"
            code, remote_sha = run_git(["rev-parse", "@{u}"], repo)
            evidence["remote_head"] = remote_sha if code == 0 else "unknown"
            code, ls_out = run_git(["ls-remote", "origin", f"refs/heads/{local_branch}"], repo)
            evidence["ls_remote_sha"] = ls_out.split()[0] if code == 0 and ls_out else "unknown"
            
        elif req.claim == "tests-pass":
            PROFILES = {
                "python-full": ["python", "-m", "pytest"],
                "npm-full": ["npm", "test"]
            }
            if req.profile not in PROFILES:
                raise ValueError(f"Unknown profile {req.profile}")
            cmd = PROFILES[req.profile]
            evidence["command"] = " ".join(cmd)
            evidence["repo_path"] = os.path.abspath(req.repo_path)
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=evidence["repo_path"])
            evidence["exit_code"] = res.returncode
            evidence["stdout_snippet"] = res.stdout[:500]
            
        elif req.claim == "running":
            evidence["pid"] = req.pid
            evidence["expected_bin_hash"] = req.expected_bin_hash
            try:
                proc = psutil.Process(req.pid)
                evidence["executable_path"] = proc.exe()
                evidence["actual_bin_hash"] = get_file_sha256(evidence["executable_path"])
            except Exception:
                pass
                
        elif req.claim == "endpoint-working":
            evidence["url"] = req.url
            evidence["expected_status"] = req.expected_status
            evidence["expected_content"] = req.expected_content
            try:
                resp = requests.get(req.url, timeout=10)
                evidence["actual_status"] = resp.status_code
                evidence["content_found"] = (req.expected_content in resp.text) if req.expected_content else False
            except Exception:
                evidence["actual_status"] = 0
                evidence["content_found"] = False
                
    except Exception as e:
        evidence["error"] = str(e)

    # Filter out nulls to match BaseModel exclude_none=True behavior exactly
    clean_evidence = {k: v for k, v in evidence.items() if v is not None}
    
    return {
        "evidence": clean_evidence,
        "signature": sign_response(clean_evidence)
    }

if __name__ == "__main__":
    print("Starting AGYWorker on 8124...")
    uvicorn.run(app, host="127.0.0.1", port=WORKER_PORT, log_level="warning")
