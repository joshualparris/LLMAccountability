import os
import subprocess
import requests
import hashlib
import hmac
import json
import tempfile
import psutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
import uuid

WORKER_PORT = 8124
PROTECTED_DIR = "C:/ProgramData/AGYVerifier"
SECRET_PATH = os.path.join(PROTECTED_DIR, "worker_secret.key")
RUNNER_PWD_PATH = os.path.join(PROTECTED_DIR, "runner_pwd.txt")

app = FastAPI(title="Antigravity Trusted Broker")

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

def sign_response(payload: dict, nonce: str) -> str:
    # Bind the nonce securely into the evidence payload before signing
    payload["nonce"] = nonce
    canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()

def run_as_runner(cmd: list, cwd: str) -> tuple[int, str]:
    if not os.path.exists(RUNNER_PWD_PATH):
        raise RuntimeError("Runner credentials not found. Trust boundary incomplete.")
        
    with open(RUNNER_PWD_PATH, "r") as f:
        pwd = f.read().strip()
        
    args_str = " ".join(f'"{arg}"' if ' ' in arg else arg for arg in cmd[1:])
    
    script = f"""
$ErrorActionPreference = "Stop"
$secStr = ConvertTo-SecureString '{pwd}' -AsPlainText -Force
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "{cmd[0]}"
$psi.Arguments = '{args_str}'
$psi.UserName = "AGYRunner"
$psi.Password = $secStr
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = "{cwd}"
$psi.CreateNoWindow = $true

try {{
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    
    $result = @{{
        ExitCode = $p.ExitCode
        Stdout = $stdout
        Stderr = $stderr
    }}
    $result | ConvertTo-Json -Compress
}} catch {{
    $err = @{{ ExitCode = -1; Stdout = ""; Stderr = $_.Exception.Message }}
    $err | ConvertTo-Json -Compress
}}
"""
    with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as f:
        f.write(script)
        script_path = f.name
        
    try:
        res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path], 
                             capture_output=True, text=True, check=True)
        out_json = json.loads(res.stdout.strip())
        return out_json.get("ExitCode", -1), out_json.get("Stdout", "")
    except Exception as e:
        return -1, str(e)
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)

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
    job_nonce = str(uuid.uuid4())
    evidence["job_id"] = job_nonce
    
    try:
        if req.claim == "pushed":
            repo = os.path.abspath(req.repo_path)
            evidence["repo_path"] = repo
            code, _ = run_as_runner(["git", "fetch", "origin"], repo)
            evidence["fetched_remote"] = (code == 0)
            code, status_out = run_as_runner(["git", "status", "--porcelain"], repo)
            evidence["working_tree_clean"] = (code == 0 and len(status_out) == 0)
            code, local_branch = run_as_runner(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo)
            code, local_sha = run_as_runner(["git", "rev-parse", "HEAD"], repo)
            evidence["local_head"] = local_sha if code == 0 else "unknown"
            code, remote_sha = run_as_runner(["git", "rev-parse", "@{u}"], repo)
            evidence["remote_head"] = remote_sha if code == 0 else "unknown"
            code, ls_out = run_as_runner(["git", "ls-remote", "origin", f"refs/heads/{local_branch}"], repo)
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
            
            code, stdout = run_as_runner(cmd, evidence["repo_path"])
            evidence["exit_code"] = code
            evidence["stdout_snippet"] = stdout[:500]
            
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

    clean_evidence = {k: v for k, v in evidence.items() if v is not None}
    
    return {
        "evidence": clean_evidence,
        "signature": sign_response(clean_evidence, job_nonce)
    }

if __name__ == "__main__":
    print("Starting AGYWorker Broker on 8124...")
    uvicorn.run(app, host="127.0.0.1", port=WORKER_PORT, log_level="warning")
