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