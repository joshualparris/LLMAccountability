import pytest
import subprocess
import json
import time
import sys
import os

def run_ps1_wrapper(cmd, timeout=2):
    args_str = " ".join(f'"{arg}"' if ' ' in arg else arg for arg in cmd[1:])
    
    script = f'''
param(
    [string]$TargetCmd,
    [string]$TargetArgs,
    [string]$TargetCwd
)
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class JobObject {{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll")]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll")]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
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
    [DllImport("kernel32.dll")]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);
}}
"@

$hJob = [JobObject]::CreateJobObject([IntPtr]::Zero, [string]::Empty)
if ($hJob -eq [IntPtr]::Zero) {{
    throw "Failed to create Job Object"
}}

try {{
    $limit = New-Object JobObject+JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    $limit.BasicLimitInformation.LimitFlags = 0x2000 # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][JobObject+JOBOBJECT_EXTENDED_LIMIT_INFORMATION])
    $res = [JobObject]::SetInformationJobObject($hJob, 9, [ref]$limit, $size)
    if (-not $res) {{
        throw "Failed to set Job Object information"
    }}

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $TargetCmd
    $psi.Arguments = $TargetArgs
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $TargetCwd
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    
    $assigned = [JobObject]::AssignProcessToJobObject($hJob, $p.Handle)
    if (-not $assigned) {{
        [JobObject]::TerminateJobObject($hJob, 1) | Out-Null
        $p.Kill()
        throw "Failed to assign process to Job Object"
    }}

    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    
    $timeoutMs = {timeout * 1000}
    $exited = $p.WaitForExit($timeoutMs)
    if (-not $exited) {{
        [JobObject]::TerminateJobObject($hJob, 1) | Out-Null
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
    
    [System.Threading.Tasks.Task]::WaitAll($outTask, $errTask)
    
    $result = @{{
        ExitCode = $p.ExitCode
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
    [JobObject]::CloseHandle($hJob) | Out-Null
}}
'''
    with open("temp_test.ps1", "w") as f:
        f.write(script)
        
    res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "temp_test.ps1", "-TargetCmd", cmd[0], "-TargetArgs", args_str, "-TargetCwd", "."], capture_output=True, text=True, timeout=timeout+10)
    os.remove("temp_test.ps1")
    try:
        return json.loads(res.stdout.strip())
    except json.JSONDecodeError:
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        raise

def test_runner_normal():
    res = run_ps1_wrapper(["python", "-c", "print('hello')"])
    assert res["ExitCode"] == 0
    assert "hello" in res["Stdout"]
    assert not res["TimedOut"]

def test_runner_stdout_heavy():
    res = run_ps1_wrapper(["python", "-c", "print('A' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stdout"]) >= 100000
    assert not res["TimedOut"]

def test_runner_stderr_heavy():
    res = run_ps1_wrapper(["python", "-c", "import sys; sys.stderr.write('B' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stderr"]) >= 100000
    assert not res["TimedOut"]

def test_runner_both_heavy():
    res = run_ps1_wrapper(["python", "-c", "import sys; print('A' * 100000); sys.stderr.write('B' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stdout"]) >= 100000
    assert len(res["Stderr"]) >= 100000
    assert not res["TimedOut"]

def test_runner_timeout_kills_child():
    res = run_ps1_wrapper(["python", "-c", "import time; time.sleep(10)"], timeout=1)
    assert res["ExitCode"] == -1
    assert res["TimedOut"] is True

def test_runner_timeout_kills_descendants():
    # Spawn a control process that should NOT be killed
    control_proc = subprocess.Popen(["python", "-c", "import time; time.sleep(20)"])
    control_pid = control_proc.pid

    # The child will write its own PID and the grandchild's PID to pids.txt, then sleep.
    # The grandchild will just sleep.
    child_script = """import subprocess, os, time
gc = subprocess.Popen(['python', '-c', 'import time; time.sleep(20)'])
with open('pids.txt', 'w') as f:
    f.write(f'{os.getpid()},{gc.pid}')
time.sleep(20)
"""
    with open("child.py", "w") as f:
        f.write(child_script)
        
    if os.path.exists("pids.txt"):
        os.remove("pids.txt")

    # Start the test wrapper in a separate thread so we can let it run and time out
    res = run_ps1_wrapper(["python", "child.py"], timeout=3)
    
    # Verify timeout occurred
    assert res["TimedOut"] is True
    
    # Verify the PIDs were recorded
    assert os.path.exists("pids.txt")
    with open("pids.txt", "r") as f:
        pids = f.read().strip().split(',')
        child_pid = int(pids[0])
        grandchild_pid = int(pids[1])
        
    import psutil
    
    # Assert child and grandchild are DEAD
    assert not psutil.pid_exists(child_pid)
    assert not psutil.pid_exists(grandchild_pid)
    
    # Assert control process is ALIVE
    assert psutil.pid_exists(control_pid)
    
    # Cleanup control process
    control_proc.kill()
    os.remove("child.py")
    os.remove("pids.txt")
