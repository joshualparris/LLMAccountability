import pytest
from unittest.mock import patch, MagicMock
from agy_worker import app
from fastapi.testclient import TestClient
import agy_worker

client = TestClient(app)

def test_worker_timeout_evidence(tmp_path):
    # Case 8: Timeout returns explicit timed-out diagnostic evidence
    # Case 9: Timeout does not return trustworthy test metrics
    with patch("agy_worker.run_as_runner") as mock_runner, \
         patch("agy_worker.get_secret", return_value=b"test_secret"), \
         patch("agy_worker.os.environ.copy", return_value={}), \
         patch("agy_worker._workspace_fingerprint", return_value=("fp", 10)), \
         patch("agy_worker.SCRATCH_DIR", str(tmp_path), create=True):
        
        mock_runner.return_value = {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "spawn_error": "",
            "timed_out": True
        }
        res = client.post("/execute", json={
            "job_id": "test",
            "repo_path": ".",
            "claim": "tests-pass",
            "profile": "python-full"
        })
        
        assert res.status_code == 200
        ev = res.json()["evidence"]
        assert ev["timed_out"] is True
        assert ev["diagnostic_reason"] == "test execution timed out"
        assert "tests" not in ev
        assert "passed" not in ev

def test_worker_incomplete_reportlog_after_timeout(tmp_path):
    # Case 10: Incomplete reportlog after timeout cannot produce PASS
    # Even if there is a report.jsonl, timed_out=True must trump it.
    
    report_dir = tmp_path / "dummy"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / "report.jsonl"
    report_file.write_text('{"$report_type": "SessionFinish", "exitstatus": 0}')
    
    with patch("agy_worker.run_as_runner") as mock_runner, \
         patch("agy_worker.get_secret", return_value=b"test_secret"), \
         patch("agy_worker._workspace_fingerprint", return_value=("fp", 10)), \
         patch("agy_worker.uuid.uuid4", return_value="dummy"), \
         patch("agy_worker.SCRATCH_DIR", str(tmp_path), create=True):
         
        mock_runner.return_value = {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "spawn_error": "",
            "timed_out": True
        }
        res = client.post("/execute", json={
            "job_id": "test",
            "repo_path": ".",
            "claim": "tests-pass",
            "profile": "python-full"
        })
    
    assert res.status_code == 200
    ev = res.json()["evidence"]
    assert ev["timed_out"] is True
    assert ev["diagnostic_reason"] == "test execution timed out"
    assert "tests" not in ev

# 11, 12, 13 are implicitly tested by the existing tests in test_v2_pytest_reportlog.py,
# but we can add a quick sanity check to ensure the new run_as_runner mock integration works cleanly.

def test_legitimate_run_still_parses(tmp_path):
    # Case 11: Legitimate completed pytest/reportlog run still parses normally
    report_dir = tmp_path / "dummy"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / "report.jsonl"
    report_file.write_text('{"$report_type": "TestReport", "nodeid": "t1", "when": "setup", "outcome": "passed"}\n'
                           '{"$report_type": "TestReport", "nodeid": "t1", "when": "call", "outcome": "passed"}\n'
                           '{"$report_type": "TestReport", "nodeid": "t1", "when": "teardown", "outcome": "passed"}\n'
                           '{"$report_type": "SessionFinish", "exitstatus": 0}')
    
    with patch("agy_worker.run_as_runner") as mock_runner, \
         patch("agy_worker.get_secret", return_value=b"test_secret"), \
         patch("agy_worker._workspace_fingerprint", return_value=("fp", 10)), \
         patch("agy_worker.uuid.uuid4", return_value="dummy"), \
         patch("agy_worker.SCRATCH_DIR", str(tmp_path), create=True):
         
        mock_runner.return_value = {
            "exit_code": 0,
            "stdout": "pytest success",
            "stderr": "",
            "spawn_error": "",
            "timed_out": False
        }
        res = client.post("/execute", json={
            "job_id": "test",
            "repo_path": ".",
            "claim": "tests-pass",
            "profile": "python-full"
        })
    
    assert res.status_code == 200
    ev = res.json()["evidence"]
    assert not ev.get("timed_out")
    assert ev.get("diagnostic_reason") is None
    assert ev["tests"] == 1
    assert ev["passed"] == 1
