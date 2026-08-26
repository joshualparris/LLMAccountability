import pytest
import subprocess
import os
import uuid

def test_sebatchlogonright_lsa_integration():
    test_user = f"AGYTest_{uuid.uuid4().hex[:6]}"
    pwd = f"Password_{uuid.uuid4().hex[:6]}!"
    subprocess.run(["powershell", "-NoProfile", "-Command", f"$sec = ConvertTo-SecureString '{pwd}' -AsPlainText -Force; New-LocalUser -Name '{test_user}' -Password $sec"], check=True)
    
    try:
        with open("install_service.ps1", "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        script_chunk = []
        in_chunk = False
        
        for line in lines:
            if "# --- BEGIN LSA HELPER ---" in line:
                in_chunk = True
            if in_chunk:
                script_chunk.append(line)
                if "# --- END LSA HELPER ---" in line:
                    break
        
        lsa_code = "".join(script_chunk)
        
        test_ps1 = f"""
{lsa_code}

$targetAccount = "$env:COMPUTERNAME\{test_user}"
$sid = (New-Object System.Security.Principal.NTAccount($targetAccount)).Translate([System.Security.Principal.SecurityIdentifier])

$initiallyHas = [LsaWrapper]::HasRight($sid, 'SeBatchLogonRight')
if ($initiallyHas) {{ throw 'Test user should not have SeBatchLogonRight initially.' }}

Grant-LsaRight -AccountName $targetAccount -Right 'SeBatchLogonRight'

$finallyHas = [LsaWrapper]::HasRight($sid, 'SeBatchLogonRight')
if (-not $finallyHas) {{ throw 'Verification failed: Test user was not granted SeBatchLogonRight.' }}

Write-Host "LSA_INTEGRATION_PASS"
"""
        
        ps_script_path = "test_lsa_chunk.ps1"
        with open(ps_script_path, "w", encoding="utf-8") as f:
            f.write(test_ps1)
            
        result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps_script_path], capture_output=True, text=True)
        assert result.returncode == 0, f"LSA chunk failed: {result.stderr}\nSTDOUT: {result.stdout}"
        assert "LSA_INTEGRATION_PASS" in result.stdout
        
        # Cleanup the granted right using the wrapper
        cleanup_ps1 = f"""
{lsa_code}
$targetAccount = "$env:COMPUTERNAME\{test_user}"
$sid = (New-Object System.Security.Principal.NTAccount($targetAccount)).Translate([System.Security.Principal.SecurityIdentifier])
[LsaWrapper]::RevokeRight($sid, 'SeBatchLogonRight')
"""
        with open("test_lsa_cleanup.ps1", "w", encoding="utf-8") as f:
            f.write(cleanup_ps1)
            
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "test_lsa_cleanup.ps1"], check=True)
        
    finally:
        subprocess.run(["powershell", "-NoProfile", "-Command", f"Remove-LocalUser -Name '{test_user}'"], check=False)
        if os.path.exists("test_lsa_chunk.ps1"):
            os.remove("test_lsa_chunk.ps1")
        if os.path.exists("test_lsa_cleanup.ps1"):
            os.remove("test_lsa_cleanup.ps1")

def test_no_secedit_configure():
    with open("install_service.ps1", "r", encoding="utf-8") as f:
        content = f.read().lower()
    assert "secedit.exe /configure" not in content
    assert "secedit /configure" not in content