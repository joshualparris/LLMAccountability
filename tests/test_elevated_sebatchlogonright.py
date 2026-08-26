import pytest
import subprocess
import os
import uuid

# This test requires elevation. Do not include in unprivileged CI.
# Usage: python -m pytest tests/test_elevated_sebatchlogonright.py

def test_sebatchlogonright_integration():
    test_user = f"AGYTest_{uuid.uuid4().hex[:6]}"
    
    # 1. Create the user
    pwd = f"Password_{uuid.uuid4().hex[:6]}!"
    subprocess.run(["powershell", "-NoProfile", "-Command", f"$sec = ConvertTo-SecureString '{pwd}' -AsPlainText -Force; New-LocalUser -Name '{test_user}' -Password $sec"], check=True)
    
    try:
        # 2. Extract the SeBatchLogonRight logic from install_service.ps1
        with open("install_service.ps1", "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        script_chunk = []
        in_chunk = False
        
        # Add the helper function manually
        script_chunk.append("function Invoke-NativeCommand { param([scriptblock]$Command); & $Command; if ($LASTEXITCODE -ne 0) { throw 'Native command failed' } }\n")
        
        for line in lines:
            if "Configuring local security policy for SeBatchLogonRight..." in line:
                in_chunk = True
            if in_chunk:
                script_chunk.append(line)
                if "SeBatchLogonRight successfully verified" in line:
                    break
        
        chunk_code = "".join(script_chunk)
        # Replace $WorkerUser with our test user
        chunk_code = chunk_code.replace("$WorkerUser", f"'{test_user}'")
        
        # 3. Execute the extracted logic
        ps_script_path = "test_chunk.ps1"
        with open(ps_script_path, "w", encoding="utf-8") as f:
            f.write(chunk_code)
            
        result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps_script_path], capture_output=True, text=True)
        assert result.returncode == 0, f"Installer chunk failed: {result.stderr}\n\nSTDOUT: {result.stdout}"
        
        # The installer chunk now inherently verifies the postcondition and exits non-zero if it fails!
        assert "SeBatchLogonRight successfully verified for" in result.stdout
        
    finally:
        # Cleanup
        subprocess.run(["powershell", "-NoProfile", "-Command", f"Remove-LocalUser -Name '{test_user}'"], check=False)
        if os.path.exists("test_chunk.ps1"):
            os.remove("test_chunk.ps1")