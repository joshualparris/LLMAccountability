$ErrorActionPreference = "Stop"

function Invoke-NativeProcessWithTimeout {
    param(
        [string]$FilePath, 
        [string[]]$ArgumentList, 
        [int]$TimeoutSeconds = 30
    )
    $procInfo = New-Object System.Diagnostics.ProcessStartInfo
    $procInfo.FileName = $FilePath
    $procInfo.Arguments = $ArgumentList -join ' '
    $procInfo.UseShellExecute = $false
    $procInfo.CreateNoWindow = $true
    
    $process = [System.Diagnostics.Process]::Start($procInfo)
    $exited = $process.WaitForExit($TimeoutSeconds * 1000)
    
    if (-not $exited) {
        $process.Kill()
        throw "Process $FilePath timed out after $TimeoutSeconds seconds."
    }
    if ($process.ExitCode -ne 0) {
        throw "Process $FilePath exited with code $($process.ExitCode)."
    }
}

# --- BEGIN LSA HELPER ---
$csharp = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;

public class LsaWrapper {
    [DllImport("advapi32.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
    public static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, int AccessMask, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
    public static extern uint LsaAddAccountRights(IntPtr PolicyHandle, byte[] AccountSid, LSA_UNICODE_STRING[] UserRights, int CountOfRights);

    [DllImport("advapi32.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
    public static extern uint LsaRemoveAccountRights(IntPtr PolicyHandle, byte[] AccountSid, bool AllRights, LSA_UNICODE_STRING[] UserRights, int CountOfRights);

    [DllImport("advapi32.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
    public static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, byte[] AccountSid, out IntPtr UserRights, out int CountOfRights);

    [DllImport("advapi32.dll")]
    public static extern int LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll")]
    public static extern uint LsaFreeMemory(IntPtr Buffer);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LSA_UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;
    }

    const int POLICY_LOOKUP_NAMES = 0x00000800;
    const int POLICY_CREATE_ACCOUNT = 0x00000010;
    const int POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;

    public static void GrantRight(SecurityIdentifier sid, string right) {
        IntPtr policyHandle = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attrs = new LSA_OBJECT_ATTRIBUTES();
            attrs.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out policyHandle);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));

            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = new LSA_UNICODE_STRING();
            rights[0].Buffer = right;
            rights[0].Length = (ushort)(right.Length * 2);
            rights[0].MaximumLength = (ushort)((right.Length + 1) * 2);

            status = LsaAddAccountRights(policyHandle, sidBytes, rights, 1);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
        } finally {
            if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
        }
    }

    public static void RevokeRight(SecurityIdentifier sid, string right) {
        IntPtr policyHandle = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attrs = new LSA_OBJECT_ATTRIBUTES();
            attrs.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out policyHandle);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));

            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = new LSA_UNICODE_STRING();
            rights[0].Buffer = right;
            rights[0].Length = (ushort)(right.Length * 2);
            rights[0].MaximumLength = (ushort)((right.Length + 1) * 2);

            status = LsaRemoveAccountRights(policyHandle, sidBytes, false, rights, 1);
            if (status != 0) {
                int err = LsaNtStatusToWinError(status);
                if (err != 2) throw new Win32Exception(err);
            }
        } finally {
            if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
        }
    }

    public static bool HasRight(SecurityIdentifier sid, string right) {
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr userRightsPtr = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attrs = new LSA_OBJECT_ATTRIBUTES();
            attrs.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, out policyHandle);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));

            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            int count = 0;
            status = LsaEnumerateAccountRights(policyHandle, sidBytes, out userRightsPtr, out count);
            if (status != 0) {
                int err = LsaNtStatusToWinError(status);
                if (err == 2) return false;
                throw new Win32Exception(err);
            }

            IntPtr current = userRightsPtr;
            for (int i = 0; i < count; i++) {
                LSA_UNICODE_STRING lsaStr = (LSA_UNICODE_STRING)Marshal.PtrToStructure(current, typeof(LSA_UNICODE_STRING));
                if (string.Equals(lsaStr.Buffer, right, StringComparison.OrdinalIgnoreCase)) return true;
                current = (IntPtr)((long)current + Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
            }
            return false;
        } finally {
            if (userRightsPtr != IntPtr.Zero) LsaFreeMemory(userRightsPtr);
            if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
        }
    }
}
'@
Add-Type -TypeDefinition $csharp

function Grant-LsaRight {
    param([string]$AccountName, [string]$Right)
    $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier])
    
    if ([LsaWrapper]::HasRight($sid, "SeDenyBatchLogonRight")) {
        throw "CRITICAL: Account $AccountName is explicitly denied $Right. Cannot proceed."
    }
    
    [LsaWrapper]::GrantRight($sid, $Right)
    
    if (-not [LsaWrapper]::HasRight($sid, $Right)) {
        throw "$Right verification failed for $AccountName"
    }
}
# --- END LSA HELPER ---

$RepoRoot = $PSScriptRoot
$ProtectedDir = "C:\ProgramData\AGYVerifier"

$ServiceName = "AGYVerifierService"
$ServiceExe = Join-Path $RepoRoot "dist\agy_service.exe"

$WorkerName = "AGYVerifierWorker"
$WorkerExe = Join-Path $RepoRoot "dist\agy_worker.exe"
$WorkerUser = "AGYWorker"

$RunnerUser = "AGYRunner"

if (-not (Test-Path $ServiceExe)) { Write-Error "Missing agy_service.exe"; exit 1 }
if (-not (Test-Path $WorkerExe)) { Write-Error "Missing agy_worker.exe"; exit 1 }

# --- User Creation ---
Write-Host "Creating trusted local broker account ($WorkerUser)..."
$WorkerPasswordStr = ([guid]::NewGuid().ToString() + "A1!")
$WorkerSecure = ConvertTo-SecureString -String $WorkerPasswordStr -AsPlainText -Force
if (-not (Get-LocalUser -Name $WorkerUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $WorkerUser -Password $WorkerSecure -PasswordNeverExpires -Description "Trusted verification broker" | Out-Null
} else {
    Set-LocalUser -Name $WorkerUser -Password $WorkerSecure
}

Write-Host "Creating untrusted local runner account ($RunnerUser)..."
$RunnerPasswordStr = ([guid]::NewGuid().ToString() + "B2@")
$RunnerSecure = ConvertTo-SecureString -String $RunnerPasswordStr -AsPlainText -Force
if (-not (Get-LocalUser -Name $RunnerUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $RunnerUser -Password $RunnerSecure -PasswordNeverExpires -Description "Disposable untrusted runner" | Out-Null
} else {
    Set-LocalUser -Name $RunnerUser -Password $RunnerSecure
}

Write-Host "Configuring local security policy for SeBatchLogonRight via LSA API..."
try {
    Grant-LsaRight -AccountName "$env:COMPUTERNAME\$WorkerUser" -Right "SeBatchLogonRight"
    Write-Host "SeBatchLogonRight successfully verified for $WorkerUser."
} catch {
    Write-Error "Failed to grant SeBatchLogonRight: $_"
    exit 1
}


# --- Directory & Base ACLs ---
Write-Host "Securing protected directory before cryptographic initialization..."
if (-not (Test-Path $ProtectedDir)) { New-Item -ItemType Directory -Path $ProtectedDir | Out-Null }

$SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "None", "None", "Allow")
$AdminAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "None", "None", "Allow")
$WorkerAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($WorkerUser, "ReadAndExecute", "None", "None", "Allow")
$WorkerRead = New-Object System.Security.AccessControl.FileSystemAccessRule($WorkerUser, "Read", "None", "None", "Allow")

# Directory gets strictly SYSTEM and Administrators full control, disabling inheritance
$DirAcl = Get-Acl $ProtectedDir
$DirAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in $DirAcl.Access) { $DirAcl.RemoveAccessRule($rule) | Out-Null }
$SysDirRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminDirRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$DirAcl.AddAccessRule($SysDirRule)
$DirAcl.AddAccessRule($AdminDirRule)
Set-Acl -Path $ProtectedDir -AclObject $DirAcl

# --- Cryptographic Migration ---
Write-Host "Handling cryptographic boundary and archiving legacy ledgers..."
if (Test-Path "$ProtectedDir\private.pem") { Remove-Item "$ProtectedDir\private.pem" -Force }
if (Test-Path "$ProtectedDir\worker_secret.key") { Remove-Item "$ProtectedDir\worker_secret.key" -Force }
if (Test-Path "$ProtectedDir\runner_pwd.txt") { Remove-Item "$ProtectedDir\runner_pwd.txt" -Force }

if (Test-Path "$ProtectedDir\protected_ledger.jsonl") {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    Write-Host "Archiving legacy ledger to archived_ledger_$Timestamp.jsonl..."
    Rename-Item -Path "$ProtectedDir\protected_ledger.jsonl" -NewName "archived_ledger_$Timestamp.jsonl"
    if (Test-Path "$ProtectedDir\public.pem") {
        Rename-Item -Path "$ProtectedDir\public.pem" -NewName "archived_public_$Timestamp.pem"
    }
}

Write-Host "Generating new HMAC worker secret and saving runner credentials..."
$SecretBytes = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($SecretBytes)
[System.IO.File]::WriteAllBytes("$ProtectedDir\worker_secret.key", $SecretBytes)
[System.IO.File]::WriteAllText("$ProtectedDir\runner_pwd.txt", $RunnerPasswordStr)

# --- Binary Deployment ---
Write-Host "Deploying frozen binaries..."
Copy-Item -Path $ServiceExe -Destination "$ProtectedDir\agy_service.exe" -Force
Copy-Item -Path $WorkerExe -Destination "$ProtectedDir\agy_worker.exe" -Force

# --- Granular File ACLs ---
Write-Host "Applying strict file-level ACLs..."
function Set-StrictAcl($FileName, $AccessRule) {
    $FilePath = "$ProtectedDir\$FileName"
    if (Test-Path $FilePath) {
        $FileAcl = Get-Acl $FilePath
        $FileAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in $FileAcl.Access) { $FileAcl.RemoveAccessRule($rule) | Out-Null }
        $FileAcl.AddAccessRule($SystemAccess)
        $FileAcl.AddAccessRule($AdminAccess)
        if ($null -ne $AccessRule) { $FileAcl.AddAccessRule($AccessRule) }
        Set-Acl -Path $FilePath -AclObject $FileAcl
    }
}

# The broker (AGYWorker) needs the secret, runner credentials, and its own executable
Set-StrictAcl "worker_secret.key" $WorkerRead
Set-StrictAcl "runner_pwd.txt" $WorkerRead
Set-StrictAcl "agy_worker.exe" $WorkerAccess

# --- Workspace Permissions for AGYRunner ---
$WorkspaceDir = (Get-Item $RepoRoot).Parent.FullName
Write-Host "Configuring AGYRunner read-only access to workspace: $WorkspaceDir"
if (Test-Path $WorkspaceDir) {
    $WorkspaceAcl = Get-Acl $WorkspaceDir
    $RunnerRead = New-Object System.Security.AccessControl.FileSystemAccessRule($RunnerUser, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $RunnerDenyWrite = New-Object System.Security.AccessControl.FileSystemAccessRule($RunnerUser, "Write", "ContainerInherit,ObjectInherit", "None", "Deny")
    $WorkspaceAcl.AddAccessRule($RunnerDenyWrite)
    $WorkspaceAcl.AddAccessRule($RunnerRead)
    Set-Acl -Path $WorkspaceDir -AclObject $WorkspaceAcl
}

# --- Scheduled Tasks Registration ---
Write-Host "Registering SYSTEM Notary Task..."
if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false }
$ActionSvc = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_service.exe" -WorkingDirectory $ProtectedDir
$TriggerSvc = New-ScheduledTaskTrigger -AtStartup
$PrincipalSvc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$SettingsSvc = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $ServiceName -Action $ActionSvc -Trigger $TriggerSvc -Principal $PrincipalSvc -Settings $SettingsSvc -Description "Protected Verification Service" | Out-Null

Write-Host "Registering Trusted Broker Task..."
if (Get-ScheduledTask -TaskName $WorkerName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $WorkerName -Confirm:$false }
$ActionWkr = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_worker.exe" -WorkingDirectory $ProtectedDir
$TriggerWkr = New-ScheduledTaskTrigger -AtStartup
$SettingsWkr = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $WorkerName -Action $ActionWkr -Trigger $TriggerWkr -Settings $SettingsWkr -User "$env:COMPUTERNAME\$WorkerUser" -Password $WorkerPasswordStr -RunLevel Limited -Description "Trusted Broker Service" | Out-Null

Write-Host "Recording Installation Hashes..."
Write-Host "agy_service.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_service.exe" -Algorithm SHA256).Hash)"
Write-Host "agy_worker.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_worker.exe" -Algorithm SHA256).Hash)"

Write-Host "Starting all services..."
Start-ScheduledTask -TaskName $ServiceName
Start-ScheduledTask -TaskName $WorkerName

Write-Host "Verifying service health and establishing public.pem ACL..."
$MaxWait = 30
$Passed = $false

$PubKeyPath = "$ProtectedDir\public.pem"
$AclSet = $false

for ($i = 0; $i -lt $MaxWait; $i++) {
    Start-Sleep -Seconds 1
    
    if (-not $AclSet -and (Test-Path $PubKeyPath)) {
        # Establish fail-closed ACLs on public.pem
        $PubAcl = Get-Acl $PubKeyPath
        $PubAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in $PubAcl.Access) { $PubAcl.RemoveAccessRule($rule) | Out-Null }
        $PubAcl.AddAccessRule($SystemAccess)
        $PubAcl.AddAccessRule($AdminAccess)
        $UsersRead = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Read", "None", "None", "Allow")
        $PubAcl.AddAccessRule($UsersRead)
        Set-Acl -Path $PubKeyPath -AclObject $PubAcl
        
        $TestAcl = Get-Acl $PubKeyPath
        $hasUsers = $false
        foreach ($r in $TestAcl.Access) {
            if ($r.IdentityReference -eq "BUILTIN\Users" -and $r.FileSystemRights -match "Read") { $hasUsers = $true }
            if ($r.IdentityReference -eq "BUILTIN\Users" -and $r.FileSystemRights -match "Write") { throw "CRITICAL: Users granted Write access to public.pem" }
        }
        if (-not $hasUsers) { throw "CRITICAL: Failed to grant Users read access to public.pem" }
        
        Write-Host "public.pem ACL established safely."
        Write-Host "Public Key Fingerprint (SHA256): $((Get-FileHash $PubKeyPath -Algorithm SHA256).Hash)"
        $AclSet = $true
    }
    
    $SvcState = (Get-ScheduledTask -TaskName $ServiceName).State
    $WkrState = (Get-ScheduledTask -TaskName $WorkerName).State
    
    $Port8123 = Test-NetConnection -ComputerName 127.0.0.1 -Port 8123 -InformationLevel Quiet -WarningAction SilentlyContinue
    $Port8124 = Test-NetConnection -ComputerName 127.0.0.1 -Port 8124 -InformationLevel Quiet -WarningAction SilentlyContinue
    
    if ($SvcState -eq 'Running' -and $WkrState -eq 'Running' -and $Port8123 -and $Port8124) {
        $Passed = $true
        break
    }
}

if (-not $Passed) {
    Write-Error "NOT ESTABLISHED. Services failed to reach healthy Running/LISTENING state."
    exit 1
}

Write-Host "Three-Tier Trust Boundary established successfully. The Notary and Broker are running."