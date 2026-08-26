$ErrorActionPreference = "Stop"

function Invoke-NativeCommand {
    param([scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $($LASTEXITCODE): $($Command.ToString())"
    }
}

$AppPath = "C:\dev\LLMAccountabilityApp"
$ProtectedDir = "C:\ProgramData\AGYVerifier"

$ServiceName = "AGYVerifierService"
$ServiceExe = "$AppPath\dist\agy_service.exe"

$WorkerName = "AGYVerifierWorker"
$WorkerExe = "$AppPath\dist\agy_worker.exe"
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

Write-Host "Configuring local security policy for SeBatchLogonRight..."
$tempInf = Join-Path $env:TEMP ("agy-" + [guid]::NewGuid() + ".inf")
$tempDb  = Join-Path $env:TEMP ("agy-" + [guid]::NewGuid() + ".sdb")
$tempLog = Join-Path $env:TEMP ("agy-" + [guid]::NewGuid() + ".log")

Invoke-NativeCommand { secedit.exe /export /cfg $tempInf /areas USER_RIGHTS }

$secPolContent = Get-Content $tempInf -Encoding Unicode

$workerSid = (New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$WorkerUser")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$workerSidTarget = "*$workerSid"

$denyLines = $secPolContent | Where-Object { $_ -match "^\s*SeDenyBatchLogonRight\s*=" }
foreach ($denyLine in $denyLines) {
    if ($denyLine -match [regex]::Escape($workerSidTarget)) {
        Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
        Write-Error "CRITICAL: AGYWorker is explicitly denied log on as a batch job (SeDenyBatchLogonRight). Cannot proceed."
        exit 1
    }
}

$updated = $false
$hasPrivSection = $false
$newContent = @()

foreach ($line in $secPolContent) {
    if ($line -match "^\s*\[Privilege Rights\]") {
        $hasPrivSection = $true
    }
    
    if ($line -match "^\s*SeBatchLogonRight\s*=") {
        if ($line -notmatch [regex]::Escape($workerSidTarget)) {
            $line = "$line,$workerSidTarget"
            $updated = $true
        }
    }
    $newContent += $line
}

if (-not $hasPrivSection) {
    $newContent += "[Privilege Rights]"
    $newContent += "SeBatchLogonRight = $workerSidTarget"
    $updated = $true
} else {
    $batchFound = $secPolContent | Where-Object { $_ -match "^\s*SeBatchLogonRight\s*=" }
    if (-not $batchFound) {
        $finalContent = @()
        foreach ($line in $newContent) {
            $finalContent += $line
            if ($line -match "^\s*\[Privilege Rights\]") {
                $finalContent += "SeBatchLogonRight = $workerSidTarget"
                $updated = $true
            }
        }
        $newContent = $finalContent
    }
}

if ($updated) {
    $newContent | Out-File -FilePath $tempInf -Encoding Unicode
    
    secedit.exe /configure /db $tempDb /cfg $tempInf /overwrite /areas USER_RIGHTS /log $tempLog | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "--- SECEDIT LOG ---"
        if (Test-Path $tempLog) { Get-Content $tempLog | Write-Host }
        Write-Host "--- GENERATED INF ---"
        if (Test-Path $tempInf) { Get-Content $tempInf | Write-Host }
        
        Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
        Remove-Item $tempLog -Force -ErrorAction SilentlyContinue
        Write-Error "secedit configure failed with exit code $LASTEXITCODE"
        exit 1
    }
}

# 9. MOST IMPORTANT: verify the postcondition.
$tempVerifyInf = Join-Path $env:TEMP ("agy-verify-" + [guid]::NewGuid() + ".inf")
Invoke-NativeCommand { secedit.exe /export /cfg $tempVerifyInf /areas USER_RIGHTS }

$verifyContent = Get-Content $tempVerifyInf -Encoding Unicode
$verified = $false
foreach ($line in $verifyContent) {
    if ($line -match "^\s*SeBatchLogonRight\s*=") {
        if ($line -match [regex]::Escape($workerSidTarget)) {
            $verified = $true
            break
        }
    }
}

Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
Remove-Item $tempLog -Force -ErrorAction SilentlyContinue
Remove-Item $tempVerifyInf -Force -ErrorAction SilentlyContinue

if (-not $verified) {
    Write-Error "SeBatchLogonRight verification failed: SID $workerSidTarget not found in re-exported policy."
    exit 1
}
Write-Host "SeBatchLogonRight successfully verified for $WorkerUser."


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

Write-Host "Verifying service health..."
$MaxWait = 30
$Passed = $false

for ($i = 0; $i -lt $MaxWait; $i++) {
    Start-Sleep -Seconds 1
    
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