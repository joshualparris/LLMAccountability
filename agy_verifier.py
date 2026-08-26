import argparse
import psutil
import requests
import subprocess
import os
import sys
import json
import hashlib
from datetime import datetime, timezone
import uuid

AUDIT_LOG_FILE = os.path.abspath(os.environ.get("AGY_AUDIT_LOG", "agy_verification_audit.jsonl"))

def get_last_hash() -> str:
    if not os.path.exists(AUDIT_LOG_FILE):
        return "0" * 64
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                return "0" * 64
            last_record = json.loads(lines[-1])
            return last_record["hash"]
    except Exception as e:
        print(f"VERIFICATION FAILED: Audit log is corrupt or unreadable: {e}", file=sys.stderr)
        sys.exit(1)

def validate_ledger():
    if not os.path.exists(AUDIT_LOG_FILE):
        return
    with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if not lines:
        return
        
    prev_hash = "0" * 64
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            print(f"VERIFICATION FAILED: Audit log corrupt at line {i+1}", file=sys.stderr)
            sys.exit(1)
            
        expected_hash = record.get("hash")
        
        temp_record = {
            "timestamp": record["timestamp"],
            "claim": record["claim"],
            "status": record["status"],
            "evidence": record["evidence"]
        }
        if "error" in record:
            temp_record["error"] = record["error"]
            
        temp_record["previous_hash"] = prev_hash
        
        canonical_json = json.dumps(temp_record, sort_keys=True)
        calculated_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
        
        if calculated_hash != expected_hash:
            print(f"VERIFICATION FAILED: Ledger tampered or corrupted at line {i+1}!", file=sys.stderr)
            sys.exit(1)
            
        prev_hash = expected_hash

def append_audit_log(record: dict):
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def get_self_hash() -> str:
    hasher = hashlib.sha256()
    with open(os.path.abspath(__file__), 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def generate_certificate(claim: str, status: str, evidence: dict, error: str = None) -> dict:
    evidence["verifier_hash"] = get_self_hash()
    
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "claim": claim,
        "status": status,
        "evidence": evidence,
    }
    if error:
        record["error"] = error
        
    prev_hash = get_last_hash()
    record["previous_hash"] = prev_hash
    
    canonical_json = json.dumps(record, sort_keys=True)
    new_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
    
    record["hash"] = new_hash
    cert_id = f"AGY-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{new_hash[:8]}"
    record["certificate_id"] = cert_id
    
    append_audit_log(record)
    return record

def print_result(record: dict):
    print(json.dumps(record, indent=2))
    if record["status"] != "PASS":
        sys.exit(1)
    sys.exit(0)

def run_git(cmd: list, cwd: str) -> tuple[int, str]:
    try:
        res = subprocess.run(["git"] + cmd, cwd=cwd, capture_output=True, text=True, check=False)
        return res.returncode, res.stdout.strip()
    except Exception as e:
        return -1, str(e)

def get_file_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Antigravity Independent Evidence Verifier CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    certify_parser = subparsers.add_parser("certify", help="Certifies a specific claim based on independent observed evidence.")
    certify_parser.add_argument("--claim", required=True, choices=["pushed", "tests-pass", "running", "endpoint-working"])
    certify_parser.add_argument("--repo-path", default=".")
    certify_parser.add_argument("--test-command")
    certify_parser.add_argument("--pid", type=int)
    certify_parser.add_argument("--expected-bin-hash")
    certify_parser.add_argument("--url")
    certify_parser.add_argument("--expected-status", type=int, default=200)
    certify_parser.add_argument("--expected-content")

    args = parser.parse_args()

    if args.command == "certify":
        # Fail closed: must validate entire ledger before certifying
        validate_ledger()
        
        evidence = {}
        status = "UNKNOWN"
        error = None
        claim = args.claim

        try:
            if claim == "pushed":
                evidence["repo_path"] = os.path.abspath(args.repo_path)
                
                code, out = run_git(["fetch", "origin"], args.repo_path)
                evidence["fetched_remote"] = (code == 0)
                if code != 0:
                    raise ValueError("Failed to fetch remote origin")

                code, status_out = run_git(["status", "--porcelain"], args.repo_path)
                evidence["working_tree_clean"] = (code == 0 and len(status_out) == 0)
                if not evidence["working_tree_clean"]:
                    raise ValueError("Working tree is dirty or has untracked files")

                code, local_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], args.repo_path)
                evidence["branch"] = local_branch

                code, local_sha = run_git(["rev-parse", "HEAD"], args.repo_path)
                evidence["local_head"] = local_sha

                code, remote_sha = run_git(["rev-parse", "@{u}"], args.repo_path)
                if code != 0:
                     raise ValueError("No upstream branch configured")
                evidence["remote_head"] = remote_sha

                if local_sha == remote_sha:
                    status = "PASS"
                else:
                    raise ValueError("Local HEAD does not match remote HEAD")

            elif claim == "tests-pass":
                if not args.test_command:
                    raise ValueError("Missing --test-command")
                
                evidence["command"] = args.test_command
                evidence["repo_path"] = os.path.abspath(args.repo_path)
                
                code, local_sha = run_git(["rev-parse", "HEAD"], args.repo_path)
                evidence["commit_sha"] = local_sha if code == 0 else "unknown"
                
                code, status_out = run_git(["status", "--porcelain"], args.repo_path)
                evidence["dirty_working_tree"] = (code != 0 or len(status_out) > 0)

                res = subprocess.run(args.test_command, shell=True, capture_output=True, text=True, cwd=args.repo_path)
                evidence["exit_code"] = res.returncode
                evidence["stdout_snippet"] = res.stdout[:500]

                if res.returncode == 0:
                    status = "PASS"
                else:
                    raise ValueError(f"Tests failed with exit code {res.returncode}")

            elif claim == "running":
                if not args.pid:
                    raise ValueError("Missing --pid")
                
                evidence["pid"] = args.pid
                
                if not psutil.pid_exists(args.pid):
                    raise ValueError(f"Process with PID {args.pid} does not exist")
                
                proc = psutil.Process(args.pid)
                if proc.status() == psutil.STATUS_ZOMBIE:
                    raise ValueError("Process is a zombie")

                try:
                    exe_path = proc.exe()
                    evidence["executable_path"] = exe_path
                    
                    actual_hash = get_file_sha256(exe_path)
                    evidence["actual_bin_hash"] = actual_hash
                    
                    if args.expected_bin_hash:
                        evidence["expected_bin_hash"] = args.expected_bin_hash
                        if actual_hash != args.expected_bin_hash:
                            raise ValueError("Binary hash does not match expected hash (stale binary?)")

                    evidence["start_time"] = datetime.fromtimestamp(proc.create_time(), timezone.utc).isoformat()
                    evidence["command_line"] = proc.cmdline()
                    status = "PASS"
                    
                except psutil.AccessDenied:
                    raise ValueError("Access denied reading process information")

            elif claim == "endpoint-working":
                if not args.url:
                    raise ValueError("Missing --url")
                
                evidence["url"] = args.url
                evidence["expected_status"] = args.expected_status
                
                try:
                    resp = requests.get(args.url, timeout=10)
                    evidence["actual_status"] = resp.status_code
                    
                    if resp.status_code != args.expected_status:
                        raise ValueError(f"Status {resp.status_code} != {args.expected_status}")
                        
                    if args.expected_content:
                        evidence["expected_content"] = args.expected_content
                        evidence["content_snippet"] = resp.text[:500]
                        if args.expected_content not in resp.text:
                            raise ValueError("Expected content not found in response")
                            
                    status = "PASS"
                except requests.exceptions.RequestException as e:
                    raise ValueError(f"Request failed: {str(e)}")

        except Exception as e:
            status = "FAIL"
            error = str(e)

        record = generate_certificate(claim, status, evidence, error)
        print_result(record)

if __name__ == "__main__":
    main()
