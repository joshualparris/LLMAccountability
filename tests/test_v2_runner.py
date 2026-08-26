import pytest
from agy_worker import run_as_runner
import tempfile
import os

# We mock subprocess.run to simulate run_as_runner PowerShell output
def test_runner_schema_success(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": 0, "Stdout": "success output", "Stderr": "some stderr", "SpawnError": ""})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    # Mock RUNNER_PWD_PATH
    temp_dir = tempfile.mkdtemp()
    pwd_path = os.path.join(temp_dir, "runner_pwd.txt")
    with open(pwd_path, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], ".")
    assert res["exit_code"] == 0
    assert res["stdout"] == "success output"
    assert res["stderr"] == "some stderr"
    assert res["spawn_error"] == ""

def test_runner_schema_child_exit_1(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": 1, "Stdout": "failed", "Stderr": "error output", "SpawnError": ""})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    temp_dir = tempfile.mkdtemp()
    pwd_path = os.path.join(temp_dir, "runner_pwd.txt")
    with open(pwd_path, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], ".")
    assert res["exit_code"] == 1
    assert res["stderr"] == "error output"
    assert res["spawn_error"] == ""

def test_runner_schema_spawn_failure(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": -1, "Stdout": "", "Stderr": "", "SpawnError": "Cannot find file"})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    temp_dir = tempfile.mkdtemp()
    pwd_path = os.path.join(temp_dir, "runner_pwd.txt")
    with open(pwd_path, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], ".")
    assert res["exit_code"] == -1
    assert res["spawn_error"] == "Cannot find file"