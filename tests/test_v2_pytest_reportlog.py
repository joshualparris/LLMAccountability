import pytest
import os
import json
from unittest.mock import patch, MagicMock
import agy_worker
from agy_worker import ExecuteRequest

def simulate_worker(tmp_path, log_records, exit_code=0):
    report_path = tmp_path / "test-job" / "report.jsonl"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as f:
        for rec in log_records:
            if isinstance(rec, str):
                f.write(rec + "\n")
            else:
                f.write(json.dumps(rec) + "\n")

    req = ExecuteRequest(claim="tests-pass", job_id="test-job", profile="python-full", repo_url="test", workspace_dir="C:/test", pid=0, expected_bin_hash="")
    
    with patch("agy_worker.run_as_runner") as mock_run:
        mock_run.return_value = {"exit_code": exit_code, "stdout": "pytest 8.2.2", "stderr": "", "spawn_error": ""}
        
        mock_uuid = MagicMock()
        mock_uuid.__str__.return_value = "test-job"
        with patch("agy_worker.uuid.uuid4", return_value=mock_uuid):
            with patch("agy_worker._workspace_fingerprint", return_value=("fake_fp", 100)):
                with patch("agy_worker.get_secret", return_value=b"secret"):
                    with patch.dict(agy_worker.__dict__, {"SCRATCH_DIR": str(tmp_path)}):
                        res = agy_worker.execute(req)
                        return res.get("evidence", {})

def test_missing_reportlog(tmp_path):
    ev = simulate_worker(tmp_path, [])
    assert ev.get("diagnostic_reason") == "pytest report log missing or empty"

def test_malformed_json(tmp_path):
    ev = simulate_worker(tmp_path, ["{bad_json"])
    assert "failed to parse reportlog" in ev.get("diagnostic_reason")

def test_missing_session_finish(tmp_path):
    ev = simulate_worker(tmp_path, [
        {"$report_type": "TestReport", "nodeid": "t1", "when": "call", "outcome": "passed"}
    ])
    assert ev.get("diagnostic_reason") == "pytest report log missing SessionFinish"

def test_mismatched_exitstatus(tmp_path):
    ev = simulate_worker(tmp_path, [
        {"$report_type": "SessionFinish", "exitstatus": 1}
    ], exit_code=0)
    assert ev.get("diagnostic_reason") == "pytest process exit code does not match report-log SessionFinish"

def test_unknown_report_type_ignored(tmp_path):
    ev = simulate_worker(tmp_path, [
        {"$report_type": "UnknownType", "some_key": "val"},
        {"$report_type": "TestReport", "nodeid": "t1", "when": "setup", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t1", "when": "call", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t1", "when": "teardown", "outcome": "passed"},
        {"$report_type": "SessionFinish", "exitstatus": 0}
    ], exit_code=0)
    assert not ev.get("diagnostic_reason")
    assert ev["tests"] == 1
    assert ev["passed"] == 1

def test_various_outcomes(tmp_path):
    logs = [
        {"$report_type": "TestReport", "nodeid": "t1", "when": "setup", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t1", "when": "call", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t1", "when": "teardown", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t2", "when": "setup", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t2", "when": "call", "outcome": "failed"},
        {"$report_type": "TestReport", "nodeid": "t2", "when": "teardown", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t3", "when": "setup", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t3", "when": "call", "outcome": "skipped"},
        {"$report_type": "TestReport", "nodeid": "t3", "when": "teardown", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t4", "when": "setup", "outcome": "failed"},
        {"$report_type": "TestReport", "nodeid": "t5", "when": "setup", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t5", "when": "call", "outcome": "passed"},
        {"$report_type": "TestReport", "nodeid": "t5", "when": "teardown", "outcome": "failed"},
        {"$report_type": "TestReport", "nodeid": "t6", "when": "setup", "outcome": "skipped"},
        {"$report_type": "SessionFinish", "exitstatus": 0}
    ]
    ev = simulate_worker(tmp_path, logs, exit_code=0)
    assert not ev.get("diagnostic_reason")
    assert ev["tests"] == 6
    assert ev["passed"] == 1
    assert ev["failures"] == 1
    assert ev["skipped"] == 2
    assert ev["errors"] == 2

def test_92_passing_events(tmp_path):
    logs = []
    for i in range(92):
        nid = f"test_{i}"
        logs.extend([
            {"$report_type": "TestReport", "nodeid": nid, "when": "setup", "outcome": "passed"},
            {"$report_type": "TestReport", "nodeid": nid, "when": "call", "outcome": "passed"},
            {"$report_type": "TestReport", "nodeid": nid, "when": "teardown", "outcome": "passed"},
        ])
    logs.append({"$report_type": "SessionFinish", "exitstatus": 0})
    ev = simulate_worker(tmp_path, logs, exit_code=0)
    assert not ev.get("diagnostic_reason")
    assert ev["tests"] == 92
    assert ev["passed"] == 92
    assert ev["failures"] == 0
    assert ev["skipped"] == 0
    assert ev["errors"] == 0