import pytest
from agy_worker import run_as_runner
import tempfile
import os

def test_runner_missing_credential(monkeypatch):
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", "does_not_exist.txt")
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert "not found" in res["spawn_error"]
    assert res["timed_out"] is False

def test_runner_empty_credential(monkeypatch):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", path)
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert "empty" in res["spawn_error"]
    assert res["timed_out"] is False
    os.remove(path)

def test_runner_schema_success(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": 0, "Stdout": "success output", "Stderr": "some stderr", "SpawnError": "", "TimedOut": False})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    fd, pwd_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == 0
    assert res["stdout"] == "success output"
    assert res["stderr"] == "some stderr"
    assert res["spawn_error"] == ""
    assert res["timed_out"] is False
    os.remove(pwd_path)

def test_runner_decode_failure(monkeypatch):
    import subprocess
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = "Some random error from powershell"
            stderr = "PowerShell crashed"
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    fd, pwd_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert "decode failure" in res["spawn_error"]
    assert res["timed_out"] is False
    os.remove(pwd_path)

def test_runner_inner_timeout(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": -1, "Stdout": "", "Stderr": "", "SpawnError": "", "TimedOut": True})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    fd, pwd_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert res["timed_out"] is True
    os.remove(pwd_path)

def test_runner_outer_timeout(monkeypatch):
    import subprocess
    
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="dummy", timeout=5)
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    fd, pwd_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert "Python subprocess timed out waiting" in res["spawn_error"]
    assert res["timed_out"] is True
    os.remove(pwd_path)

def test_runner_create_process_failure(monkeypatch):
    import subprocess
    import json
    
    def mock_run(*args, **kwargs):
        class MockRes:
            returncode = 0
            stdout = json.dumps({"ExitCode": -1, "Stdout": "", "Stderr": "", "SpawnError": "CreateProcessWithLogonW failed with error 1326", "TimedOut": False})
            stderr = ""
        return MockRes()
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    fd, pwd_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f: f.write("dummy")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    res = run_as_runner(["dummy"], timeout=5, cwd=".")
    assert res["exit_code"] == -1
    assert "CreateProcessWithLogonW failed" in res["spawn_error"]
    assert res["timed_out"] is False
    os.remove(pwd_path)
