import pytest
from fastapi.testclient import TestClient
from agy_worker import app

client = TestClient(app)

def test_worker_execute_pushed():
    import json
    import os
    
    import agy_worker
    from unittest.mock import patch
    
    executed_cmds = []
    
    def mock_run(cmd, *, timeout, cwd, env=None):
        executed_cmds.append(cmd)
        if "rev-parse" in cmd and "--abbrev-ref" in cmd:
            return {"exit_code": 0, "stdout": "main\n", "stderr": "", "spawn_error": "", "timed_out": False}
        return {"exit_code": 0, "stdout": "mock output\n", "stderr": "", "spawn_error": "", "timed_out": False}
        
    with patch("agy_worker.get_secret", return_value=b"secret"), patch("agy_worker.RUNNER_PWD_PATH", "dummy.txt"), patch("agy_worker.run_as_runner", side_effect=mock_run):
        repo = os.path.abspath(".")
        response = client.post("/execute", json={
            "claim": "pushed",
            "repo_path": repo
        })
        assert response.status_code == 200
        data = response.json()
        assert "evidence" in data
        evidence = data["evidence"]
        
        assert any(cmd[:3] == ["git", "remote", "get-url"] for cmd in executed_cmds)
        assert any(cmd[:3] == ["git", "status", "--porcelain"] for cmd in executed_cmds)
        assert any(cmd[:4] == ["git", "rev-parse", "--abbrev-ref", "HEAD"] for cmd in executed_cmds)
        assert any(cmd[:3] == ["git", "ls-remote", "origin"] for cmd in executed_cmds)
        
        assert "git_remote_url" in evidence
        assert "git_status" in evidence
        assert "git_rev_parse_branch" in evidence
        assert "git_rev_parse_head" in evidence
        
        assert "error" not in evidence
        assert "diagnostic_reason" not in evidence

def test_worker_execute_pushed_git_fails():
    import json
    import os
    
    import agy_worker
    from unittest.mock import patch
    
    def mock_run(cmd, *, timeout, cwd, env=None):
        if "status" in cmd:
            return {"exit_code": 128, "stdout": "", "stderr": "fatal: not a git repository", "spawn_error": "", "timed_out": False}
        return {"exit_code": 0, "stdout": "", "stderr": "", "spawn_error": "", "timed_out": False}
        
    with patch("agy_worker.get_secret", return_value=b"secret"), patch("agy_worker.RUNNER_PWD_PATH", "dummy.txt"), patch("agy_worker.run_as_runner", side_effect=mock_run):
        repo = os.path.abspath(".")
        response = client.post("/execute", json={
            "claim": "pushed",
            "repo_path": repo
        })
        assert response.status_code == 200
        data = response.json()
        assert "evidence" in data
        evidence = data["evidence"]
        
        assert evidence.get("diagnostic_reason") == "git status failed"
        assert evidence["git_status"]["exit_code"] == 128
