$AppPath = "C:\dev\LLMAccountabilityApp"
$ProtectedDir = "C:\ProgramData\AGYVerifier"

$ServiceName = "AGYVerifierService"
$ServiceExe = "$AppPath\dist\agy_service.exe"

$WorkerName = "AGYVerifierWorker"
$WorkerExe = "$AppPath\dist\agy_worker.exe"
$WorkerUser = "AGYWorker"

if (-not (Test-Path $ServiceExe)) { Write-Error "Missing agy_service.exe"; exit 1 }
if (-not (Test-Path $WorkerExe)) { Write-Error "Missing agy_worker.exe"; exit 1 }

Write-Host "Creating local worker account ($WorkerUser)..."
$PlainTextPassword = ([guid]::NewGuid().ToString() + "A1!")
$SecurePassword = ConvertTo-SecureString -String $PlainTextPassword -AsPlainText -Force
if (-not (Get-LocalUser -Name $WorkerUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $WorkerUser -Password $SecurePassword -PasswordNeverExpires -Description "Unprivileged verification worker" | Out-Null
} else {
    Set-LocalUser -Name $WorkerUser -Password $SecurePassword
}

Write-Host "Creating protected directory..."
if (-not (Test-Path $ProtectedDir)) { New-Item -ItemType Directory -Path $ProtectedDir | Out-Null }

Write-Host "Discarding any tainted pre-boundary cryptographic keys..."
if (Test-Path "$ProtectedDir\private.pem") { Remove-Item "$ProtectedDir\private.pem" -Force }
if (Test-Path "$ProtectedDir\public.pem") { Remove-Item "$ProtectedDir\public.pem" -Force }
if (Test-Path "$ProtectedDir\worker_secret.key") { Remove-Item "$ProtectedDir\worker_secret.key" -Force }

Write-Host "Generating new HMAC worker secret..."
$SecretBytes = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($SecretBytes)
[System.IO.File]::WriteAllBytes("$ProtectedDir\worker_secret.key", $SecretBytes)

Write-Host "Copying compiled executables..."
Copy-Item -Path $ServiceExe -Destination "$ProtectedDir\agy_service.exe" -Force
Copy-Item -Path $WorkerExe -Destination "$ProtectedDir\agy_worker.exe" -Force

# --- ACL Setup ---
Write-Host "Locking down ACLs..."
$SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "None", "None", "Allow")
$WorkerAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($WorkerUser, "ReadAndExecute", "None", "None", "Allow")

# 1. Directory itself (List only for SYSTEM, so no inherited access)
$DirAcl = Get-Acl $ProtectedDir
$DirAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in $DirAcl.Access) { $DirAcl.RemoveAccessRule($rule) | Out-Null }
$DirAcl.AddAccessRule(New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))
Set-Acl -Path $ProtectedDir -AclObject $DirAcl

# Ensure files inherit from the strictly locked directory, then add specific worker access
function Grant-WorkerRead($FilePath) {
    if (Test-Path $FilePath) {
        $FileAcl = Get-Acl $FilePath
        $FileAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in $FileAcl.Access) { $FileAcl.RemoveAccessRule($rule) | Out-Null }
        $FileAcl.AddAccessRule($SystemAccess)
        $FileAcl.AddAccessRule($WorkerAccess)
        Set-Acl -Path $FilePath -AclObject $FileAcl
    }
}

Grant-WorkerRead "$ProtectedDir\agy_worker.exe"
Grant-WorkerRead "$ProtectedDir\worker_secret.key"

Write-Host "Registering SYSTEM Notary Task..."
if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false }
$ActionSvc = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_service.exe" -WorkingDirectory $ProtectedDir
$TriggerSvc = New-ScheduledTaskTrigger -AtStartup
$PrincipalSvc = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $ServiceName -Action $ActionSvc -Trigger $TriggerSvc -Principal $PrincipalSvc -Description "Protected Verification Service" | Out-Null

Write-Host "Registering Unprivileged Worker Task..."
if (Get-ScheduledTask -TaskName $WorkerName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $WorkerName -Confirm:$false }
$ActionWkr = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_worker.exe" -WorkingDirectory $ProtectedDir
$TriggerWkr = New-ScheduledTaskTrigger -AtStartup
$PrincipalWkr = New-ScheduledTaskPrincipal -UserId $WorkerUser -LogonType Password
Register-ScheduledTask -TaskName $WorkerName -Action $ActionWkr -Trigger $TriggerWkr -Principal $PrincipalWkr -Password $PlainTextPassword -Description "Unprivileged Worker Service" | Out-Null

Write-Host "Recording Installation Hashes..."
Write-Host "agy_service.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_service.exe" -Algorithm SHA256).Hash)"
Write-Host "agy_worker.exe SHA256: $((Get-FileHash "$ProtectedDir\agy_worker.exe" -Algorithm SHA256).Hash)"

Write-Host "Starting the services..."
Start-ScheduledTask -TaskName $ServiceName
Start-ScheduledTask -TaskName $WorkerName

Write-Host "Trust Boundary established securely."
