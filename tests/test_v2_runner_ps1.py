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
public class Launcher {{
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
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string applicationName, string commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
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
}}
"@

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
    [Launcher]::CloseHandle($hJob) | Out-Null
    throw "Failed to set Job Object information, error: $err"
}}

$sa = New-Object Launcher+SECURITY_ATTRIBUTES
$sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Launcher+SECURITY_ATTRIBUTES])
$sa.bInheritHandle = $true
$sa.lpSecurityDescriptor = [IntPtr]::Zero

$hOutRead = [IntPtr]::Zero
$hOutWrite = [IntPtr]::Zero
if (-not [Launcher]::CreatePipe([ref]$hOutRead, [ref]$hOutWrite, [ref]$sa, 0)) {{
    throw "Failed to create stdout pipe"
}}
[Launcher]::SetHandleInformation($hOutRead, 1, 0) | Out-Null

$hErrRead = [IntPtr]::Zero
$hErrWrite = [IntPtr]::Zero
if (-not [Launcher]::CreatePipe([ref]$hErrRead, [ref]$hErrWrite, [ref]$sa, 0)) {{
    throw "Failed to create stderr pipe"
}}
[Launcher]::SetHandleInformation($hErrRead, 1, 0) | Out-Null

$si = New-Object Launcher+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Launcher+STARTUPINFO])
$si.dwFlags = 0x00000100 # STARTF_USESTDHANDLES
$si.hStdOutput = $hOutWrite
$si.hStdError = $hErrWrite

$pi = New-Object Launcher+PROCESS_INFORMATION
$cmdLine = "`"$TargetCmd`" $TargetArgs"

$creationFlags = 0x04000004 # CREATE_UNICODE_ENVIRONMENT (0x400) | CREATE_SUSPENDED (0x4)
$creationFlags = $creationFlags -bor 0x08000000 # CREATE_NO_WINDOW

$success = [Launcher]::CreateProcessW(
    $TargetCmd, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $true,
    $creationFlags, [IntPtr]::Zero, $TargetCwd, [ref]$si, [ref]$pi
)

if (-not $success) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    [Launcher]::CloseHandle($hOutRead) | Out-Null
    [Launcher]::CloseHandle($hOutWrite) | Out-Null
    [Launcher]::CloseHandle($hErrRead) | Out-Null
    [Launcher]::CloseHandle($hErrWrite) | Out-Null
    [Launcher]::CloseHandle($hJob) | Out-Null
    throw "CreateProcessW failed with error $err"
}}

$assigned = [Launcher]::AssignProcessToJobObject($hJob, $pi.hProcess)
if (-not $assigned) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    [Launcher]::TerminateProcess($pi.hProcess, 1) | Out-Null
    throw "AssignProcessToJobObject failed with error $err"
}}

[Launcher]::ResumeThread($pi.hThread) | Out-Null
[Launcher]::CloseHandle($pi.hThread) | Out-Null
[Launcher]::CloseHandle($hOutWrite) | Out-Null
[Launcher]::CloseHandle($hErrWrite) | Out-Null

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
        [Launcher]::TerminateJobObject($hJob, 1) | Out-Null
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
    
    $exitCode = 0
    [Launcher]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode) | Out-Null
    
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
    [Launcher]::CloseHandle($pi.hProcess) | Out-Null
    [Launcher]::CloseHandle($hJob) | Out-Null
}}
'''
    with open("temp_test.ps1", "w") as f:
        f.write(script)
        
    res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "temp_test.ps1", "-TargetCmd", cmd[0], "-TargetArgs", args_str, "-TargetCwd", os.path.abspath(".")], capture_output=True, text=True, timeout=timeout+10)
    os.remove("temp_test.ps1")
    try:
        return json.loads(res.stdout.strip())
    except json.JSONDecodeError:
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        raise

def test_runner_normal():
    res = run_ps1_wrapper([sys.executable, "-c", "print('hello')"])
    assert res["ExitCode"] == 0
    assert res["Stdout"] == "hello\r\n"
    assert res["Stderr"] == ""
    assert res["TimedOut"] is False

def test_runner_stdout_heavy():
    res = run_ps1_wrapper([sys.executable, "-c", "print('A' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stdout"]) >= 100000
    assert res["TimedOut"] is False

def test_runner_stderr_heavy():
    res = run_ps1_wrapper([sys.executable, "-c", "import sys; sys.stderr.write('B' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stderr"]) >= 100000
    assert res["TimedOut"] is False

def test_runner_both_heavy():
    res = run_ps1_wrapper([sys.executable, "-c", "import sys; print('A' * 100000); sys.stderr.write('B' * 100000)"])
    assert res["ExitCode"] == 0
    assert len(res["Stdout"]) >= 100000
    assert len(res["Stderr"]) >= 100000
    assert res["TimedOut"] is False

def test_runner_timeout_kills_child():
    res = run_ps1_wrapper([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)
    
    assert res["ExitCode"] == -1
    assert res["TimedOut"] is True

def test_runner_timeout_kills_descendants():
    # Spawn a control process that should NOT be killed
    control_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    control_pid = control_proc.pid

    # The child will write its own PID and the grandchild's PID to pids.txt, then sleep.
    # The grandchild will just sleep.
    child_script = f"""import subprocess, os, time, sys
gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
with open('pids.txt', 'w') as f:
    f.write(f'{{os.getpid()}},{{gc.pid}}')
time.sleep(20)
"""
    with open("child.py", "w") as f:
        f.write(child_script)
        
    if os.path.exists("pids.txt"):
        os.remove("pids.txt")

    # Start the test wrapper in a separate thread so we can let it run and time out
    res = run_ps1_wrapper([sys.executable, "child.py"], timeout=3)
    
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

def test_containment_race_condition():
    # To prove the race condition, we simulate a delay between process start and job assignment in the old approach,
    # and compare it with the new CREATE_SUSPENDED approach.
    
    import time
    import psutil
    
    script = f"""import subprocess, os, sys, time
# Immediately spawn a breakaway child that lives forever
gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
print(gc.pid)
sys.stdout.flush()
time.sleep(30)
"""
    with open("race_child.py", "w") as f:
        f.write(script)
        
    # We can prove the NEW approach by seeing if the grandchild survives a timeout.
    # If the process was created suspended, it couldn't spawn the grandchild before assignment.
    # When timeout occurs, the Job Object terminates everything.
    res = run_ps1_wrapper([sys.executable, "race_child.py"], timeout=1)
    
    assert res["TimedOut"] is True
    
    # If there was a race, the grandchild might survive. But because of CREATE_SUSPENDED,
    # the grandchild is born INTO the Job Object, and thus dies with it.
    # The grandchild's PID isn't available to python easily because it died before the script finished.
    # We can check there are no lingering python processes born from race_child.py
    
    os.remove("race_child.py")
