import pytest
import re
import os
import tempfile
from agy_worker import sanitize_diagnostic

def test_sanitize_diagnostic_redacts_credentials(monkeypatch):
    # Mock runner pwd
    temp_dir = tempfile.mkdtemp()
    pwd_path = os.path.join(temp_dir, "runner_pwd.txt")
    with open(pwd_path, "w") as f:
        f.write("SuperSecretRunnerPwd")
    monkeypatch.setattr("agy_worker.RUNNER_PWD_PATH", pwd_path)
    
    text = (
        "Here is my github_pat_11ABCD1234\n"
        "And ghp_abc123DEF456\n"
        "Authorization: Bearer my_token_here\n"
        "bearer something\n"
        "https://user:password@github.com/repo\n"
        "access_token='foo'\n"
        "token=bar\n"
        "api_key=\"baz\"\n"
        "password=Secret123\n"
        "SuperSecretRunnerPwd is the runner pwd\n"
        "Ordinary text should remain."
    )
    
    sanitized = sanitize_diagnostic(text)
    
    assert "github_pat_" not in sanitized
    assert "ghp_abc" not in sanitized
    assert "my_token_here" not in sanitized
    assert "bearer something" not in sanitized.lower()
    assert "user:password@" not in sanitized
    assert "foo" not in sanitized
    assert "bar" not in sanitized
    assert "baz" not in sanitized
    assert "Secret123" not in sanitized
    assert "SuperSecretRunnerPwd" not in sanitized
    
    assert "Ordinary text should remain." in sanitized
    assert "[REDACTED]" in sanitized

def test_sanitize_diagnostic_truncates():
    long_text = "A" * 1500 + "github_pat_1234"
    sanitized = sanitize_diagnostic(long_text)
    assert len(sanitized) == 1000
    assert "github_pat" not in sanitized
    assert "A" * 999 in sanitized
