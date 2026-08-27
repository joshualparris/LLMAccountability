import pytest
from v2.recipes.tests import TestsPassRecipe
from v2.recipes.git import GitPushRecipe
from v2.recipes.base import Verdict
import requests

class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
    def json(self):
        return self._json

def test_tests_recipe_spawn_failure(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"spawn_error": "File not found"}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = TestsPassRecipe()
    res = recipe.verify({"claim": "tests-pass"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE
    assert "Process spawn error" in res.reason

def test_tests_recipe_missing_evidence(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = TestsPassRecipe()
    res = recipe.verify({"claim": "tests-pass"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE
    assert "No valid exit code" in res.reason

def test_tests_recipe_exit_1(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"exit_code": 1}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = TestsPassRecipe()
    res = recipe.verify({"claim": "tests-pass"}, {})
    assert res.verdict == Verdict.FAIL

def test_tests_recipe_exit_0(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"exit_code": 0}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = TestsPassRecipe()
    res = recipe.verify({"claim": "tests-pass"}, {})
    assert res.verdict == Verdict.PASS

def test_git_recipe_fetch_failure(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"diagnostic_reason": "git fetch failed: timeout"}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE

def test_git_recipe_status_failure(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"diagnostic_reason": "git status failed"}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE

def test_git_recipe_revparse_execution_failure(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"git_rev_parse_head": {"spawn_error": "Cannot find file"}}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE

def test_git_recipe_lsremote_network_failure(monkeypatch):
    def mock_post(*args, **kwargs):
        return MockResponse({"authenticated": True, "evidence": {"git_ls_remote": {"exit_code": 128, "stderr_snippet": "fatal: Could not read from remote"}}})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.INCONCLUSIVE

def test_git_recipe_success_matching_shas(monkeypatch):
    def mock_post(*args, **kwargs):
        ev = {
            "git_rev_parse_head": {"exit_code": 0, "stdout_snippet": "abc1234"},
            "git_rev_parse_upstream": {"exit_code": 0, "stdout_snippet": "abc1234"},
            "git_ls_remote": {"exit_code": 0, "stdout_snippet": "abc1234 refs/heads/main"}
        }
        return MockResponse({"authenticated": True, "evidence": ev})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.PASS

def test_git_recipe_success_differing_shas(monkeypatch):
    def mock_post(*args, **kwargs):
        ev = {
            "git_rev_parse_head": {"exit_code": 0, "stdout_snippet": "abc1234"},
            "git_rev_parse_upstream": {"exit_code": 0, "stdout_snippet": "abc1234"},
            "git_ls_remote": {"exit_code": 0, "stdout_snippet": "def5678 refs/heads/main"}
        }
        return MockResponse({"authenticated": True, "evidence": ev})
    monkeypatch.setattr(requests, "post", mock_post)
    
    recipe = GitPushRecipe()
    res = recipe.verify({"claim": "pushed"}, {})
    assert res.verdict == Verdict.FAIL
def test_tests_recipe_fingerprint_toctou(monkeypatch, tmp_path):
    import agy_worker
    from fastapi.testclient import TestClient
    import os

    client = TestClient(agy_worker.app)
    
    # create dummy repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "test.py").write_text("print('test')")
    
    # Mock run_as_runner to simulate the test running AND the source changing during execution
    def mock_run(cmd, cwd):
        # simulate modifying the workspace
        (repo / "test.py").write_text("print('hacked')")
        return {"exit_code": 0, "stdout": b"test passed", "stderr": b"", "spawn_error": None}
        
    monkeypatch.setattr(agy_worker, "run_as_runner", mock_run)
    monkeypatch.setattr(agy_worker, "get_secret", lambda: b"mock_secret")
    
    monkeypatch.setattr(agy_worker, "SCRATCH_DIR", str(tmp_path / "scratch"), raising=False)
    monkeypatch.setattr(agy_worker, "get_file_sha256", lambda path: "mock_hash")
    
    import subprocess
    class MockCompletedProcess:
        def __init__(self):
            self.stdout = "8.2.2\n"
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockCompletedProcess())
    
    req = {"claim": "tests-pass", "repo_path": str(repo), "profile": "python-full"}
    resp = client.post("/execute", json=req)
    assert resp.status_code == 200
    evidence = resp.json()["evidence"]
    assert evidence.get("diagnostic_reason") == "workspace changed during test execution"
    assert evidence.get("workspace_fingerprint") is None

def test_pushed_recipe_no_fetch(monkeypatch):
    import agy_worker
    import subprocess
    calls = []
    
    class MockCompletedProcess:
        def __init__(self, stdout, stderr, returncode):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode
            
    def mock_run(args, *a, **k):
        calls.append(args)
        if "rev-parse" in args and "--abbrev-ref" in args:
            return MockCompletedProcess("main\n", "", 0)
        return MockCompletedProcess("success\n", "", 0)
        
    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.setattr(agy_worker, "get_secret", lambda: b"dummy")
    
    from fastapi.testclient import TestClient
    client = TestClient(agy_worker.app)
    client.post("/execute", json={
        "id": "job-id",
        "claim": "pushed",
        "repo_path": ".",
        "profile": "python-full",
        "expected_bin_hash": "abc"
    })
    
    for call in calls:
        assert "fetch" not in call, "Worker pushed verification must NOT use fetch"

def test_tests_recipe_fingerprint_stable(monkeypatch, tmp_path):
    import agy_worker
    from fastapi.testclient import TestClient
    import os

    client = TestClient(agy_worker.app)
    
    # create dummy repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "test.py").write_text("print('test')")
    
    def mock_run(cmd, cwd):
        return {"exit_code": 0, "stdout": b"test passed", "stderr": b"", "spawn_error": None}
        
    monkeypatch.setattr(agy_worker, "run_as_runner", mock_run)
    monkeypatch.setattr(agy_worker, "get_secret", lambda: b"mock_secret")
    monkeypatch.setattr(agy_worker, "SCRATCH_DIR", str(tmp_path / "scratch"), raising=False)
    monkeypatch.setattr(agy_worker, "get_file_sha256", lambda path: "mock_hash")
    import subprocess
    class MockCompletedProcess:
        def __init__(self):
            self.stdout = "8.2.2\n"
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockCompletedProcess())
    
    req = {"claim": "tests-pass", "repo_path": str(repo), "profile": "python-full"}
    resp = client.post("/execute", json=req)
    assert resp.status_code == 200
    evidence = resp.json()["evidence"]
    assert evidence.get("workspace_fingerprint") is not None
    assert evidence.get("diagnostic_reason") is None

def test_tests_recipe_zero_metrics(monkeypatch):
    from v2.recipes.tests import TestsPassRecipe
    import json
    
    class MockRes:
        def __init__(self):
            self.status_code = 200
        def json(self):
            return {
                "status": "PASS",
                "evidence": {
                    "exit_code": 0,
                    "tests": 0,
                    "passed": 0,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "workspace_fingerprint": "abcd",
                    "workspace_file_count": 10,
                    "python_executable": "C:\\ProgramData\\AGYRuntime\\python\\Scripts\\python.exe",
                    "python_executable_sha256": "aaaa",
                    "pytest_version": "8.2.2"
                },
                "signature": "mock_sig"
            }
            
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRes())
    monkeypatch.setattr("agy_service.verify_worker_signature", lambda ev, sig: True)
    
    claim = {"type": "tests-pass", "id": "t1"}
    
    res = TestsPassRecipe().verify(claim, {})
    assert res.verdict.name == "FAIL"

