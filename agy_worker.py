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

def run_as_runner(cmd: list, cwd: str) -> dict:
    if not os.path.exists(RUNNER_PWD_PATH):
        raise RuntimeError("Runner credentials not found. Trust boundary incomplete.")
        
    with open(RUNNER_PWD_PATH, "r") as f:
        pwd = f.read().strip()
        
    args_str = " ".join(f'"{arg}"' if ' ' in arg else arg for arg in cmd[1:])
    
    script = """
param(
    [string]$TargetCmd,
    [string]$TargetArgs,
    [string]$TargetCwd
)
$ErrorActionPreference = "Stop"
$secStr = ConvertTo-SecureString $env:AGY_RUNNER_PWD -AsPlainText -Force
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TargetCmd
$psi.Arguments = $TargetArgs
$psi.UserName = "AGYRunner"
$psi.Password = $secStr
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = $TargetCwd
$psi.CreateNoWindow = $true

try {
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    
    $result = @{
        ExitCode = $p.ExitCode
        Stdout = $stdout
        Stderr = $stderr
        SpawnError = ""
    }
    $result | ConvertTo-Json -Compress
} catch {
    $err = @{ ExitCode = -1; Stdout = ""; Stderr = ""; SpawnError = $_.Exception.Message }
    $err | ConvertTo-Json -Compress
}
"""
    with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as f:
        f.write(script)
        script_path = f.name
        
    try:
        env = os.environ.copy()
        env["AGY_RUNNER_PWD"] = pwd
        res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path, 
             "-TargetCmd", cmd[0], "-TargetArgs", args_str, "-TargetCwd", cwd], 
            capture_output=True, text=True, env=env
        )
        if res.returncode != 0 and not res.stdout.strip():
            return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": f"PowerShell failure: {res.stderr}"}
            
        try:
            out_json = json.loads(res.stdout.strip())
            return {
                "exit_code": out_json.get("ExitCode", -1),
                "stdout": out_json.get("Stdout", ""),
                "stderr": out_json.get("Stderr", ""),
                "spawn_error": out_json.get("SpawnError", "")
            }
        except json.JSONDecodeError:
            return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": f"PowerShell decode failure: {res.stdout.strip()} {res.stderr.strip()}"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": str(e)}
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
            
            def run_git(args, key):
                res = run_as_runner(["git"] + args, repo)
                def redact(s):
                    s = s[:1000]
                    try:
                        s = s.replace(get_secret().decode('utf-8', errors='ignore'), "[REDACTED]")
                    except: pass
                    s = s.replace(os.environ.get("AGY_RUNNER_PWD", "NOT_SET_YET"), "[REDACTED]")
                    return s
                
                evidence[key] = {
                    "exit_code": res["exit_code"],
                    "stdout_snippet": redact(res["stdout"]),
                    "stderr_snippet": redact(res["stderr"])
                }
                if res["spawn_error"]:
                    evidence[key]["spawn_error"] = res["spawn_error"]
                return res

            res_fetch = run_git(["fetch", "origin"], "git_fetch")
            if res_fetch["exit_code"] != 0 or res_fetch["spawn_error"]:
                evidence["diagnostic_reason"] = "git fetch failed"
                
            res_status = run_git(["status", "--porcelain"], "git_status")
            if res_status["exit_code"] != 0 or res_status["spawn_error"]:
                if "diagnostic_reason" not in evidence:
                    evidence["diagnostic_reason"] = "git status failed"
                    
            res_rev = run_git(["rev-parse", "--abbrev-ref", "HEAD"], "git_rev_parse_head")
            local_branch = res_rev["stdout"].strip() if res_rev["exit_code"] == 0 else "unknown"
            evidence["local_head"] = local_branch
            
            run_git(["rev-parse", "HEAD"], "git_rev_parse_head_sha")
            run_git(["rev-parse", "@{u}"], "git_rev_parse_upstream")
            run_git(["ls-remote", "origin", f"refs/heads/{local_branch}"], "git_ls_remote")
            
        elif req.claim == "tests-pass":
            PROFILES = {
                "python-full": ["python", "-m", "pytest", "--ignore=tests/test_elevated_sebatchlogonright.py"],
                "npm-full": ["npm", "test"]
            }
            if req.profile not in PROFILES:
                raise ValueError(f"Unknown profile {req.profile}")
            cmd = PROFILES[req.profile]
            evidence["command"] = " ".join(cmd)
            evidence["repo_path"] = os.path.abspath(req.repo_path)
            
            res = run_as_runner(cmd, evidence["repo_path"])
            
            def redact(s):
                s = s[:1000]
                try:
                    s = s.replace(get_secret().decode('utf-8', errors='ignore'), "[REDACTED]")
                except: pass
                pwd = ""
                try:
                    if os.path.exists(RUNNER_PWD_PATH):
                        with open(RUNNER_PWD_PATH, "r") as f:
                            pwd = f.read().strip()
                except: pass
                if pwd: s = s.replace(pwd, "[REDACTED]")
                return s
                
            evidence["exit_code"] = res["exit_code"]
            evidence["stdout_snippet"] = redact(res["stdout"])
            evidence["stderr_snippet"] = redact(res["stderr"])
            if res["spawn_error"]:
                evidence["spawn_error"] = res["spawn_error"]
                evidence["diagnostic_reason"] = "failed to spawn tests"
            
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
