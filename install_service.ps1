# install_service.ps1
# This script sets up the true Trust Boundary.
# It registers the AGY Service to run as SYSTEM, and locks down the ProgramData directory.

$ErrorActionPreference = "Stop"

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
if (-not (Get-LocalUser -Name $WorkerUser -ErrorAction SilentlyContinue)) {
    $Password = ConvertTo-SecureString -String ([guid]::NewGuid().ToString() + "A1!") -AsPlainText -Force
    New-LocalUser -Name $WorkerUser -Password $Password -PasswordNeverExpires -Description "Unprivileged verification worker" | Out-Null
}

Write-Host "Creating protected directory..."
if (-not (Test-Path $ProtectedDir)) { New-Item -ItemType Directory -Path $ProtectedDir | Out-Null }

Write-Host "Discarding any tainted pre-boundary cryptographic keys..."
if (Test-Path "$ProtectedDir\private.pem") { Remove-Item "$ProtectedDir\private.pem" -Force }
if (Test-Path "$ProtectedDir\public.pem") { Remove-Item "$ProtectedDir\public.pem" -Force }
if (Test-Path "$ProtectedDir\worker_secret.key") { Remove-Item "$ProtectedDir\worker_secret.key" -Force }

Write-Host "Copying compiled executables..."
Copy-Item -Path $ServiceExe -Destination "$ProtectedDir\agy_service.exe" -Force
Copy-Item -Path $WorkerExe -Destination "$ProtectedDir\agy_worker.exe" -Force

Write-Host "Locking down ACLs on $ProtectedDir..."
$Acl = Get-Acl $ProtectedDir
$Acl.SetAccessRuleProtection($true, $false)
foreach ($rule in $Acl.Access) { $Acl.RemoveAccessRule($rule) | Out-Null }

$SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$WorkerAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($WorkerUser, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

$Acl.AddAccessRule($SystemAccess)
$Acl.AddAccessRule($AdminAccess)
$Acl.AddAccessRule($WorkerAccess)
Set-Acl -Path $ProtectedDir -AclObject $Acl

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
Register-ScheduledTask -TaskName $WorkerName -Action $ActionWkr -Trigger $TriggerWkr -Principal $PrincipalWkr -Description "Unprivileged Worker Service" | Out-Null

Write-Host "Starting the services..."
Start-ScheduledTask -TaskName $ServiceName
Start-ScheduledTask -TaskName $WorkerName

Write-Host "Trust Boundary established. The service is now running as SYSTEM, and the ledger/keys are protected from standard user tampering."
