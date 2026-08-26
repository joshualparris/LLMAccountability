$ErrorActionPreference = "Stop"

$AppPath = "C:\dev\LLMAccountabilityApp"
$ProtectedDir = "C:\ProgramData\AGYVerifier"

$ServiceName = "AGYVerifierService"
$ServiceExe = "$AppPath\dist\agy_service.exe"

$WorkerName = "AGYVerifierWorker"
$WorkerExe = "$AppPath\dist\agy_worker.exe"
$WorkerUser = "AGYWorker"

$RunnerName = "AGYVerifierRunner"
$RunnerExe = "$AppPath\dist\agy_runner.exe"
$RunnerUser = "AGYRunner"

if (-not (Test-Path $ServiceExe)) { Write-Error "Missing agy_service.exe"; exit 1 }
if (-not (Test-Path $WorkerExe)) { Write-Error "Missing agy_worker.exe"; exit 1 }
if (-not (Test-Path $RunnerExe)) { Write-Error "Missing agy_runner.exe"; exit 1 }

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

# --- Directory & Base ACLs (Race Condition Fix) ---
Write-Host "Securing protected directory before cryptographic initialization..."
if (-not (Test-Path $ProtectedDir)) { New-Item -ItemType Directory -Path $ProtectedDir | Out-Null }

$SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "None", "None", "Allow")
$WorkerAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($WorkerUser, "ReadAndExecute", "None", "None", "Allow")
$RunnerAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($RunnerUser, "ReadAndExecute", "None", "None", "Allow")

# Directory gets strictly SYSTEM-only full control, disabling inheritance
$DirAcl = Get-Acl $ProtectedDir
$DirAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in $DirAcl.Access) { $DirAcl.RemoveAccessRule($rule) | Out-Null }
$DirAcl.AddAccessRule(New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))
Set-Acl -Path $ProtectedDir -AclObject $DirAcl

# --- Cryptographic Migration ---
Write-Host "Handling cryptographic boundary and archiving legacy ledgers..."
if (Test-Path "$ProtectedDir\private.pem") { Remove-Item "$ProtectedDir\private.pem" -Force }
if (Test-Path "$ProtectedDir\worker_secret.key") { Remove-Item "$ProtectedDir\worker_secret.key" -Force }

if (Test-Path "$ProtectedDir\protected_ledger.jsonl") {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    Write-Host "Archiving legacy ledger to archived_ledger_$Timestamp.jsonl..."
    Rename-Item -Path "$ProtectedDir\protected_ledger.jsonl" -NewName "archived_ledger_$Timestamp.jsonl"
    if (Test-Path "$ProtectedDir\public.pem") {
        Rename-Item -Path "$ProtectedDir\public.pem" -NewName "archived_public_$Timestamp.pem"
    }
}

Write-Host "Generating new HMAC worker secret..."
$SecretBytes = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($SecretBytes)
[System.IO.File]::WriteAllBytes("$ProtectedDir\worker_secret.key", $SecretBytes)

# --- Binary Deployment ---
Write-Host "Deploying frozen binaries..."
Copy-Item -Path $ServiceExe -Destination "$ProtectedDir\agy_service.exe" -Force
Copy-Item -Path $WorkerExe -Destination "$ProtectedDir\agy_worker.exe" -Force
Copy-Item -Path $RunnerExe -Destination "$ProtectedDir\agy_runner.exe" -Force

# --- Granular File ACLs ---
Write-Host "Applying strict file-level ACLs..."
function Set-StrictAcl($FileName, $AccessRule) {
    $FilePath = "$ProtectedDir\$FileName"
    if (Test-Path $FilePath) {
        $FileAcl = Get-Acl $FilePath
        $FileAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in $FileAcl.Access) { $FileAcl.RemoveAccessRule($rule) | Out-Null }
        $FileAcl.AddAccessRule($SystemAccess) # SYSTEM always gets access
        if ($null -ne $AccessRule) { $FileAcl.AddAccessRule($AccessRule) }
        Set-Acl -Path $FilePath -AclObject $FileAcl
    }
}

# The broker (AGYWorker) needs the secret and its own executable
Set-StrictAcl "worker_secret.key" $WorkerAccess
Set-StrictAcl "agy_worker.exe" $WorkerAccess

# The runner (AGYRunner) needs ONLY its executable. It CANNOT access the secret.
Set-StrictAcl "agy_runner.exe" $RunnerAccess

# --- Scheduled Tasks Registration ---
Write-Host "Registering SYSTEM Notary Task..."
if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false }
$ActionSvc = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_service.exe" -WorkingDirectory $ProtectedDir
$TriggerSvc = New-ScheduledTaskTrigger -AtStartup
$PrincipalSvc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $ServiceName -Action $ActionSvc -Trigger $TriggerSvc -Principal $PrincipalSvc -Description "Protected Verification Service" | Out-Null

Write-Host "Registering Trusted Broker Task..."
if (Get-ScheduledTask -TaskName $WorkerName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $WorkerName -Confirm:$false }
$ActionWkr = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_worker.exe" -WorkingDirectory $ProtectedDir
$TriggerWkr = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $WorkerName -Action $ActionWkr -Trigger $TriggerWkr -User "$env:COMPUTERNAME\$WorkerUser" -Password $WorkerPasswordStr -RunLevel Limited -Description "Trusted Broker Service" | Out-Null

Write-Host "Registering Untrusted Runner Task..."
if (Get-ScheduledTask -TaskName $RunnerName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $RunnerName -Confirm:$false }
$ActionRun = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_runner.exe" -WorkingDirectory $ProtectedDir
$TriggerRun = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $RunnerName -Action $ActionRun -Trigger $TriggerRun -User "$env:COMPUTERNAME\$RunnerUser" -Password $RunnerPasswordStr -RunLevel Limited -Description "Untrusted Runner Service" | Out-Null

Write-Host "Recording Installation Hashes..."
Write-Host "agy_service.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_service.exe" -Algorithm SHA256).Hash)"
Write-Host "agy_worker.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_worker.exe" -Algorithm SHA256).Hash)"
Write-Host "agy_runner.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_runner.exe" -Algorithm SHA256).Hash)"

Write-Host "Starting all services..."
Start-ScheduledTask -TaskName $ServiceName
Start-ScheduledTask -TaskName $WorkerName
Start-ScheduledTask -TaskName $RunnerName

Write-Host "Three-Tier Trust Boundary established successfully."
