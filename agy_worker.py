import os
import subprocess
import requests
import hashlib
import hmac
import json
import tempfile
import psutil
import re
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
    payload["nonce"] = nonce
    canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()

def sanitize_diagnostic(text: str) -> str:
    if not text:
        return ""
        
    pwd = ""
    try:
        if os.path.exists(RUNNER_PWD_PATH):
            with open(RUNNER_PWD_PATH, "r") as f:
                pwd = f.read().strip()
    except Exception:
        pass
        
    if pwd:
        text = text.replace(pwd, "[REDACTED]")

    # Redact common credential patterns BEFORE truncating
    patterns = [
        r"github_pat_[a-zA-Z0-9_]+",
        r"ghp_[a-zA-Z0-9]+",
        r"(?i)bearer\s+[A-Za-z0-9\-\._~\+/]+=*",
        r"(?i)authorization:\s*bearer\s+[A-Za-z0-9\-\._~\+/]+=*",
        r"https?://[^:\s@]+:[^@\s]+@",
        r"(?i)(?:access_token|token|api_key|password)\s*[:=]\s*['\"]?[A-Za-z0-9\-\._~\+/]+['\"]?"
    ]
    
    for pat in patterns:
        text = re.sub(pat, "[REDACTED]", text)
        
    return text[:1000]

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
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def _is_relevant(rel_path: str) -> bool:
    from pathlib import Path
    _RELEVANT_EXTENSIONS = {
        ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        ".rs", ".go", ".java", ".kt", ".kts", ".scala", ".c", ".cc",
        ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".sh",
        ".ps1", ".psm1", ".toml", ".yaml", ".yml", ".json", ".xml",
        ".ini", ".cfg", ".lock",
    }
    _RELEVANT_NAMES = {"Dockerfile", "Makefile", "Justfile", "Taskfile.yml"}
    _IGNORED_PARTS = {
        ".git", ".agentwitness", ".pytest_cache", "__pycache__", "node_modules",
        "dist", "build", ".venv", "venv", "target", ".next", ".turbo",
    }
    p = Path(rel_path)
    if any(part in _IGNORED_PARTS for part in p.parts):
        return False
    return p.name in _RELEVANT_NAMES or p.suffix.lower() in _RELEVANT_EXTENSIONS

def _workspace_fingerprint(cwd: str) -> tuple[str, int]:
    import os, subprocess, hashlib
    from pathlib import Path
    
    root = Path(cwd).resolve()
    try:
        res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip():
            root = Path(res.stdout.strip())
    except Exception:
        pass
        
    paths = []
    try:
        res = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=str(root), capture_output=True, check=False)
        if res.returncode == 0:
            paths = [p.decode("utf-8", errors="surrogateescape") for p in res.stdout.split(b"\0") if p]
    except Exception:
        pass
        
    if not paths:
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {
                ".git", ".agentwitness", ".pytest_cache", "__pycache__", "node_modules",
                "dist", "build", ".venv", "venv", "target", ".next", ".turbo",
            }]
            for name in files:
                rel = str((Path(base) / name).relative_to(root)).replace("\\", "/")
                paths.append(rel)
                
    relevant = sorted({p.replace("\\", "/") for p in paths if _is_relevant(p)})
    digest = hashlib.sha256()
    count = 0
    for rel in relevant:
        path = root / rel
        if not path.is_file(): continue
        try:
            data = path.read_bytes()
        except OSError: continue
        digest.update(rel.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
        count += 1
    return digest.hexdigest(), count

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
                evidence[key] = {
                    "exit_code": res["exit_code"],
                    "stdout_snippet": sanitize_diagnostic(res["stdout"]),
                    "stderr_snippet": sanitize_diagnostic(res["stderr"])
                }
                if res["spawn_error"]:
                    evidence[key]["spawn_error"] = sanitize_diagnostic(res["spawn_error"])
                return res

            run_git(["remote", "get-url", "origin"], "git_remote_url")
            
            res_status = run_git(["status", "--porcelain"], "git_status")
            if res_status["exit_code"] != 0 or res_status["spawn_error"]:
                if "diagnostic_reason" not in evidence:
                    evidence["diagnostic_reason"] = sanitize_diagnostic("git status failed")
                    
            res_rev = run_git(["rev-parse", "--abbrev-ref", "HEAD"], "git_rev_parse_branch")
            local_branch = res_rev["stdout"].strip() if res_rev["exit_code"] == 0 else "unknown"
            evidence["local_branch"] = sanitize_diagnostic(local_branch)
            
            run_git(["rev-parse", "HEAD"], "git_rev_parse_head")
            if local_branch != "unknown":
                run_git(["ls-remote", "origin", f"refs/heads/{local_branch}"], "git_ls_remote")
            
        elif req.claim == "tests-pass":
            repo_path = os.path.abspath(req.repo_path)
            
            scratch_base = globals().get("SCRATCH_DIR", "C:\\ProgramData\\AGYScratch")
            scratch_dir = os.path.join(scratch_base, job_nonce)
            os.makedirs(scratch_dir, exist_ok=True)
            report_path = os.path.join(scratch_dir, "report.jsonl")
            
            protected_python = "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe"
            PROFILES = {
                "python-full": [protected_python, "-m", "pytest", "-p", "no:cacheprovider", "--ignore=tests/test_elevated_sebatchlogonright.py", f"--report-log={report_path}"],
                "npm-full": ["npm", "test"]
            }
            if req.profile not in PROFILES:
                raise ValueError(f"Unknown profile {req.profile}")
            cmd = PROFILES[req.profile]
            evidence["command"] = " ".join(cmd)
            evidence["repo_path"] = repo_path
            
            if req.profile == "python-full":
                evidence["python_executable"] = protected_python
                evidence["python_executable_sha256"] = get_file_sha256(protected_python)
                
                # Check pytest version
                try:
                    import subprocess
                    pv = subprocess.run([protected_python, "-c", "import pytest; print(pytest.__version__)"], capture_output=True, text=True, check=True)
                    evidence["pytest_version"] = pv.stdout.strip()
                except Exception:
                    evidence["pytest_version"] = "unknown"
            
            fp_before, fp_count_before = _workspace_fingerprint(repo_path)
            
            # Set PYTHONDONTWRITEBYTECODE=1 in the worker environment so it inherits to the runner script
            os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
            if req.profile == "python-full":
                os.environ["PYTHONPATH"] = os.path.join(repo_path, "src")
                
            res = run_as_runner(cmd, repo_path)
            
            fp_after, fp_count_after = _workspace_fingerprint(repo_path)
            
            if fp_before != fp_after or fp_count_before != fp_count_after:
                evidence["diagnostic_reason"] = "workspace changed during test execution"
                evidence["workspace_fingerprint"] = None
                evidence["workspace_file_count"] = None
            else:
                evidence["workspace_fingerprint"] = fp_after
                evidence["workspace_file_count"] = fp_count_after
            
            evidence["exit_code"] = res["exit_code"]
            evidence["stdout_snippet"] = sanitize_diagnostic(res["stdout"])
            evidence["stderr_snippet"] = sanitize_diagnostic(res["stderr"])
            if res["spawn_error"]:
                evidence["spawn_error"] = sanitize_diagnostic(res["spawn_error"])
                evidence["diagnostic_reason"] = sanitize_diagnostic("failed to spawn tests")
                
            if req.profile == "python-full":
                if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
                    evidence["diagnostic_reason"] = "pytest report log missing or empty"
                else:
                    import json
                    try:
                        tests_dict = {}
                        session_finish = None
                        with open(report_path, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                record = json.loads(line)
                                rtype = record.get("$report_type")
                                if rtype == "SessionFinish":
                                    session_finish = record
                                elif rtype == "TestReport":
                                    nodeid = record.get("nodeid")
                                    if not nodeid:
                                        continue
                                    when = record.get("when")
                                    outcome = record.get("outcome")
                                    if nodeid not in tests_dict:
                                        tests_dict[nodeid] = {"setup": None, "call": None, "teardown": None}
                                    if when in tests_dict[nodeid]:
                                        tests_dict[nodeid][when] = outcome
                        
                        if session_finish is None:
                            evidence["diagnostic_reason"] = "pytest report log missing SessionFinish"
                        elif "exitstatus" not in session_finish:
                            evidence["diagnostic_reason"] = "SessionFinish missing exitstatus"
                        elif session_finish["exitstatus"] != evidence.get("exit_code"):
                            evidence["diagnostic_reason"] = "pytest process exit code does not match report-log SessionFinish"
                        else:
                            passed = 0
                            failures = 0
                            errors = 0
                            skipped = 0
                            classified_tests = 0
                            for nodeid, phases in tests_dict.items():
                                classified = False
                                if phases["setup"] == "failed" or phases["teardown"] == "failed":
                                    errors += 1
                                    classified = True
                                elif phases["call"] == "skipped" or (phases["setup"] == "skipped" and phases["call"] is None):
                                    skipped += 1
                                    classified = True
                                elif phases["call"] == "failed":
                                    failures += 1
                                    classified = True
                                elif phases["call"] == "passed" and phases["setup"] != "failed" and phases["teardown"] != "failed":
                                    passed += 1
                                    classified = True
                                
                                if classified:
                                    classified_tests += 1

                            evidence["tests"] = classified_tests
                            evidence["passed"] = passed
                            evidence["failures"] = failures
                            evidence["errors"] = errors
                            evidence["skipped"] = skipped
                    except Exception as e:
                        evidence["diagnostic_reason"] = f"failed to parse reportlog: {e}"
                
            import shutil
            shutil.rmtree(scratch_dir, ignore_errors=True)
            
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
        evidence["error"] = sanitize_diagnostic(str(e))

    clean_evidence = {k: v for k, v in evidence.items() if v is not None}
    
    return {
        "evidence": clean_evidence,
        "signature": sign_response(clean_evidence, job_nonce)
    }

if __name__ == "__main__":
    print("Starting AGYWorker Broker on 8124...")
    uvicorn.run(app, host="127.0.0.1", port=WORKER_PORT, log_level="warning")