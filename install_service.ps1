# install_service.ps1
# This script sets up the true Trust Boundary.
# It registers the AGY Service to run as SYSTEM, and locks down the ProgramData directory.

$ErrorActionPreference = "Stop"

$AppPath = "C:\dev\LLMAccountabilityApp"
$ProtectedDir = "C:\ProgramData\AGYVerifier"
$TaskName = "AGYVerifierService"
$ServiceExe = "$AppPath\dist\agy_service.exe"

if (-not (Test-Path $ServiceExe)) {
    Write-Error "Could not find agy_service.exe. Did you freeze it with PyInstaller?"
    exit 1
}

Write-Host "Creating protected directory..."
if (-not (Test-Path $ProtectedDir)) {
    New-Item -ItemType Directory -Path $ProtectedDir | Out-Null
}

Write-Host "Discarding any tainted pre-boundary cryptographic keys..."
if (Test-Path "$ProtectedDir\private.pem") { Remove-Item "$ProtectedDir\private.pem" -Force }
if (Test-Path "$ProtectedDir\public.pem") { Remove-Item "$ProtectedDir\public.pem" -Force }

Write-Host "Copying compiled service runtime to protected directory..."
# Prevent privilege escalation and runtime poisoning by using a frozen .exe
Copy-Item -Path $ServiceExe -Destination "$ProtectedDir\agy_service.exe" -Force

Write-Host "Locking down ACLs on $ProtectedDir..."
# We want only SYSTEM and Administrators to have access.
$Acl = Get-Acl $ProtectedDir
$Acl.SetAccessRuleProtection($true, $false) # Disable inheritance

# Clear any explicit existing rules
foreach ($rule in $Acl.Access) {
    $Acl.RemoveAccessRule($rule) | Out-Null
}

$SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

$Acl.AddAccessRule($SystemAccess)
$Acl.AddAccessRule($AdminAccess)
Set-Acl -Path $ProtectedDir -AclObject $Acl

Write-Host "Registering Scheduled Task to run as SYSTEM..."
# Unregister if it already exists
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Execute the frozen executable inside the protected directory
$Action = New-ScheduledTaskAction -Execute "$ProtectedDir\agy_service.exe" -WorkingDirectory $ProtectedDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Antigravity Protected Verification Service" | Out-Null

Write-Host "Starting the service..."
Start-ScheduledTask -TaskName $TaskName

Write-Host "Trust Boundary established. The service is now running as SYSTEM, and the ledger/keys are protected from standard user tampering."
