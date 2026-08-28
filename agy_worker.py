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

def run_as_runner(cmd: list[str], timeout: int, cwd: str, env: dict = None) -> dict:
    import json
    import os
    import subprocess
    import tempfile
    
    if not os.path.exists(RUNNER_PWD_PATH):
        return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": "Runner credentials not found", "timed_out": False}
    with open(RUNNER_PWD_PATH, "r") as f:
        AGY_RUNNER_PWD = f.read().strip()
        
    if not AGY_RUNNER_PWD:
        return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": "Runner credentials empty", "timed_out": False}

    env_json = json.dumps(env or {})
    
    wrapper_env = os.environ.copy()
    wrapper_env["AGY_RUNNER_PWD"] = AGY_RUNNER_PWD
    
    # We must properly escape arguments that contain spaces
    def escape_arg(arg: str) -> str:
        if ' ' in arg or '"' in arg:
            escaped = arg.replace('"', '\\"')
            return f'"{escaped}"'
        return arg
        
    args_str = " ".join(escape_arg(arg) for arg in cmd[1:])
    
    script = f'''
param(
    [string]$TargetCmd,
    [string]$TargetArgs,
    [string]$TargetCwd,
    [string]$TargetEnvJson
)
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Launcher {{
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint LOGON_WITH_PROFILE = 0x00000001;
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {{
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {{
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }}
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(
        string userName, string domain, string password, uint logonFlags,
        string applicationName, string commandLine, uint creationFlags,
        IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {{
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }}
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {{
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public JOBOBJECT_IO_ACCOUNTING_INFO IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {{
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_IO_ACCOUNTING_INFO {{
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }}
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    public static IntPtr BuildEnvironmentBlock(Dictionary<string, string> env) {{
        if (env == null || env.Count == 0) return IntPtr.Zero;
        List<string> vars = new List<string>();
        foreach (var kvp in env) {{
            vars.Add(kvp.Key + "=" + kvp.Value);
        }}
        vars.Sort(StringComparer.OrdinalIgnoreCase);
        StringBuilder sb = new StringBuilder();
        foreach (string s in vars) {{
            sb.Append(s).Append('\\0');
        }}
        sb.Append('\\0');
        byte[] bytes = Encoding.Unicode.GetBytes(sb.ToString());
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }}
}}
"@

function Check-Handle($handle, $name) {{
    if ($handle -ne [IntPtr]::Zero) {{
        if (-not [Launcher]::CloseHandle($handle)) {{
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "CloseHandle failed for $name with error $err"
        }}
    }}
}}

$hJob = [Launcher]::CreateJobObject([IntPtr]::Zero, [string]::Empty)
if ($hJob -eq [IntPtr]::Zero) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "Failed to create Job Object, error: $err"
}}

$limit = New-Object Launcher+JOBOBJECT_EXTENDED_LIMIT_INFORMATION
$limit.BasicLimitInformation.LimitFlags = 0x2000 # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
$size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Launcher+JOBOBJECT_EXTENDED_LIMIT_INFORMATION])
$res = [Launcher]::SetInformationJobObject($hJob, 9, [ref]$limit, $size)
if (-not $res) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Check-Handle $hJob "hJob"
    throw "Failed to set Job Object information, error: $err"
}}

$sa = New-Object Launcher+SECURITY_ATTRIBUTES
$sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Launcher+SECURITY_ATTRIBUTES])
$sa.bInheritHandle = $true
$sa.lpSecurityDescriptor = [IntPtr]::Zero

$hInRead = [IntPtr]::Zero
$hInWrite = [IntPtr]::Zero
if (-not [Launcher]::CreatePipe([ref]$hInRead, [ref]$hInWrite, [ref]$sa, 0)) {{
    throw "Failed to create stdin pipe"
}}
if (-not [Launcher]::SetHandleInformation($hInWrite, 1, 0)) {{
    throw "Failed to SetHandleInformation on stdin"
}}
Check-Handle $hInWrite "hInWrite"

$hOutRead = [IntPtr]::Zero
$hOutWrite = [IntPtr]::Zero
if (-not [Launcher]::CreatePipe([ref]$hOutRead, [ref]$hOutWrite, [ref]$sa, 0)) {{
    throw "Failed to create stdout pipe"
}}
if (-not [Launcher]::SetHandleInformation($hOutRead, 1, 0)) {{
    throw "Failed to SetHandleInformation on stdout"
}}

$hErrRead = [IntPtr]::Zero
$hErrWrite = [IntPtr]::Zero
if (-not [Launcher]::CreatePipe([ref]$hErrRead, [ref]$hErrWrite, [ref]$sa, 0)) {{
    throw "Failed to create stderr pipe"
}}
if (-not [Launcher]::SetHandleInformation($hErrRead, 1, 0)) {{
    throw "Failed to SetHandleInformation on stderr"
}}

$si = New-Object Launcher+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Launcher+STARTUPINFO])
$si.dwFlags = 0x00000100 # STARTF_USESTDHANDLES
$si.hStdInput = $hInRead
$si.hStdOutput = $hOutWrite
$si.hStdError = $hErrWrite

$pi = New-Object Launcher+PROCESS_INFORMATION
$cmdLine = "`"$TargetCmd`" $TargetArgs"

$creationFlags = [Launcher]::CREATE_UNICODE_ENVIRONMENT -bor [Launcher]::CREATE_SUSPENDED -bor [Launcher]::CREATE_NO_WINDOW

$envDict = New-Object "System.Collections.Generic.Dictionary[string,string]"
$envObj = $TargetEnvJson | ConvertFrom-Json
if ($envObj) {{
    foreach ($prop in $envObj.psobject.properties) {{
        $envDict[$prop.Name] = [string]$prop.Value
    }}
}}
$envPtr = [Launcher]::BuildEnvironmentBlock($envDict)

$success = [Launcher]::CreateProcessWithLogonW(
    "AGYRunner", ".", $env:AGY_RUNNER_PWD, [Launcher]::LOGON_WITH_PROFILE,
    $TargetCmd, $cmdLine, $creationFlags, $envPtr, $TargetCwd, [ref]$si, [ref]$pi
)

if ($envPtr -ne [IntPtr]::Zero) {{
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($envPtr)
}}

if (-not $success) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Check-Handle $hInRead "hInRead"
    Check-Handle $hOutRead "hOutRead"
    Check-Handle $hOutWrite "hOutWrite"
    Check-Handle $hErrRead "hErrRead"
    Check-Handle $hErrWrite "hErrWrite"
    Check-Handle $hJob "hJob"
    throw "CreateProcessWithLogonW failed with error $err"
}}

$assigned = [Launcher]::AssignProcessToJobObject($hJob, $pi.hProcess)
if (-not $assigned) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not [Launcher]::TerminateProcess($pi.hProcess, 1)) {{
        $err2 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "AssignProcessToJobObject failed ($err), and TerminateProcess failed ($err2)"
    }}
    throw "AssignProcessToJobObject failed with error $err"
}}

$resumeRes = [Launcher]::ResumeThread($pi.hThread)
if ($resumeRes -eq 0xFFFFFFFF) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not [Launcher]::TerminateJobObject($hJob, 1)) {{
        $err2 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "ResumeThread failed ($err), and TerminateJobObject failed ($err2)"
    }}
    throw "ResumeThread failed with error $err"
}}

Check-Handle $pi.hThread "hThread"
Check-Handle $hInRead "hInRead"
Check-Handle $hOutWrite "hOutWrite"
Check-Handle $hErrWrite "hErrWrite"

try {{
    $outSafe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($hOutRead, $true)
    $outStream = New-Object System.IO.FileStream($outSafe, [System.IO.FileAccess]::Read)
    $outReader = New-Object System.IO.StreamReader($outStream)
    $outTask = $outReader.ReadToEndAsync()

    $errSafe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($hErrRead, $true)
    $errStream = New-Object System.IO.FileStream($errSafe, [System.IO.FileAccess]::Read)
    $errReader = New-Object System.IO.StreamReader($errStream)
    $errTask = $errReader.ReadToEndAsync()
    
    $timeoutMs = {timeout * 1000}
    $waitRes = [Launcher]::WaitForSingleObject($pi.hProcess, $timeoutMs)
    
    if ($waitRes -eq 0x102) {{ # WAIT_TIMEOUT
        if (-not [Launcher]::TerminateJobObject($hJob, 1)) {{
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "TerminateJobObject failed on timeout with error $err"
        }}
        $result = @{{
            ExitCode = -1
            Stdout = ""
            Stderr = ""
            SpawnError = ""
            TimedOut = $true
        }}
        $result | ConvertTo-Json -Compress
        exit 0
    }}
    elseif ($waitRes -ne 0) {{ # WAIT_OBJECT_0 is 0
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (-not [Launcher]::TerminateJobObject($hJob, 1)) {{
            $err2 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "WaitForSingleObject failed abnormally: $waitRes ($err), and TerminateJobObject failed ($err2)"
        }}
        throw "WaitForSingleObject failed abnormally: $waitRes (error $err)"
    }}
    
    [System.Threading.Tasks.Task]::WaitAll($outTask, $errTask)
    
    $exitCode = 0
    if (-not [Launcher]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode)) {{
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "GetExitCodeProcess failed with error $err"
    }}
    
    $result = @{{
        ExitCode = $exitCode
        Stdout = $outTask.Result
        Stderr = $errTask.Result
        SpawnError = ""
        TimedOut = $false
    }}
    $result | ConvertTo-Json -Compress
}} catch {{
    $err = @{{ ExitCode = -1; Stdout = ""; Stderr = ""; SpawnError = $_.Exception.Message; TimedOut = $false }}
    $err | ConvertTo-Json -Compress
}} finally {{
    $cleanupErrors = @()
    if ($pi.hProcess -ne [IntPtr]::Zero) {{
        if (-not [Launcher]::CloseHandle($pi.hProcess)) {{
            $cleanupErrors += "CloseHandle(hProcess) failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }}
    }}
    if ($hJob -ne [IntPtr]::Zero) {{
        if (-not [Launcher]::CloseHandle($hJob)) {{
            $cleanupErrors += "CloseHandle(hJob) failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }}
    }}
    if ($cleanupErrors.Count -gt 0) {{
        $err = @{{ ExitCode = -1; Stdout = ""; Stderr = ""; SpawnError = "Cleanup failed: $($cleanupErrors -join '; ')"; TimedOut = $false }}
        $err | ConvertTo-Json -Compress
    }}
}}
'''
    fd, temp_script_path = tempfile.mkstemp(suffix=".ps1", text=True)
    with os.fdopen(fd, "w") as f:
        f.write(script)
        
    try:
        res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script_path, "-TargetCmd", cmd[0], "-TargetArgs", args_str, "-TargetCwd", cwd, "-TargetEnvJson", env_json],
            capture_output=True, text=True, timeout=timeout+10, env=wrapper_env
        )
        try:
            out_json = json.loads(res.stdout.strip())
            return {
                "exit_code": out_json.get("ExitCode", -1),
                "stdout": out_json.get("Stdout", ""),
                "stderr": out_json.get("Stderr", ""),
                "spawn_error": out_json.get("SpawnError", ""),
                "timed_out": out_json.get("TimedOut", False)
            }
        except json.JSONDecodeError:
            return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": f"PowerShell decode failure: {res.stdout.strip()} {res.stderr.strip()}", "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": "", "spawn_error": "Python subprocess timed out waiting for PowerShell wrapper", "timed_out": True}
    finally:
        if os.path.exists(temp_script_path):
            os.remove(temp_script_path)

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
            
            safe_env = {
                "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows"),
                "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
                "SystemDrive": os.environ.get("SystemDrive", "C:"),
                "TEMP": scratch_base,
                "TMP": scratch_base,
                "PYTHONDONTWRITEBYTECODE": "1"
            }
            if req.profile == "python-full":
                safe_env["PYTHONPATH"] = os.path.join(repo_path, "src")
                
            timeout = 300 if req.profile == "python-full" else 120
            res = run_as_runner(cmd, timeout=timeout, cwd=repo_path, env=safe_env)
            
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
            
            if res.get("timed_out", False):
                evidence["timed_out"] = True
                evidence["diagnostic_reason"] = "test execution timed out"
                
            if res["spawn_error"]:
                evidence["spawn_error"] = sanitize_diagnostic(res["spawn_error"])
                if "diagnostic_reason" not in evidence:
                    evidence["diagnostic_reason"] = sanitize_diagnostic("failed to spawn tests")
                
            if req.profile == "python-full" and not evidence.get("timed_out", False) and "diagnostic_reason" not in evidence:
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
                        elif not tests_dict:
                            evidence["diagnostic_reason"] = "pytest report log contains no test reports"
                        else:
                            passed = 0
                            failures = 0
                            errors = 0
                            skipped = 0
                            classified_tests = 0
                            for nodeid, phases in tests_dict.items():
                                if phases["setup"] == "failed" or phases["teardown"] == "failed":
                                    errors += 1
                                    classified_tests += 1
                                elif phases["setup"] == "skipped" and phases["call"] is None:
                                    skipped += 1
                                    classified_tests += 1
                                elif phases["call"] == "skipped":
                                    skipped += 1
                                    classified_tests += 1
                                elif phases["setup"] == "passed" and phases["call"] == "failed" and phases["teardown"] is not None and phases["teardown"] != "failed":
                                    failures += 1
                                    classified_tests += 1
                                elif phases["setup"] == "passed" and phases["call"] == "passed" and phases["teardown"] is not None and phases["teardown"] != "failed":
                                    passed += 1
                                    classified_tests += 1
                                
                            if classified_tests != len(tests_dict):
                                evidence["diagnostic_reason"] = "pytest report log contains incomplete or unclassifiable test reports"
                            else:
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