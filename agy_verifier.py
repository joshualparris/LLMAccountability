import argparse
import sys
import json
import requests
import subprocess
import os
import psutil
from datetime import datetime, timezone
import hashlib

SERVICE_URL = "http://127.0.0.1:8123/certify"

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
    parser = argparse.ArgumentParser(description="Antigravity RPC Client (v1.3)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    certify_parser = subparsers.add_parser("certify")
    certify_parser.add_argument("--claim", required=True, choices=["pushed", "tests-pass", "running", "endpoint-working"])
    certify_parser.add_argument("--repo-path", default=".")
    certify_parser.add_argument("--profile")
    certify_parser.add_argument("--pid", type=int)
    certify_parser.add_argument("--expected-bin-hash")
    certify_parser.add_argument("--url")
    certify_parser.add_argument("--expected-status", type=int, default=200)
    certify_parser.add_argument("--expected-content")

    args = parser.parse_args()

    if args.command == "certify":
        evidence = {}
        
        if args.claim == "pushed":
            repo_path = os.path.abspath(args.repo_path)
            code, out = run_git(["fetch", "origin"], repo_path)
            evidence["fetched_remote"] = (code == 0)
            
            code, status_out = run_git(["status", "--porcelain"], repo_path)
            evidence["working_tree_clean"] = (code == 0 and len(status_out) == 0)
            
            code, local_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], repo_path)
            code, local_sha = run_git(["rev-parse", "HEAD"], repo_path)
            evidence["local_head"] = local_sha if code == 0 else "unknown"
            
            code, remote_sha = run_git(["rev-parse", "@{u}"], repo_path)
            evidence["remote_head"] = remote_sha if code == 0 else "unknown"
            
            code, ls_remote_out = run_git(["ls-remote", "origin", f"refs/heads/{local_branch}"], repo_path)
            evidence["ls_remote_sha"] = ls_remote_out.split()[0] if code == 0 and ls_remote_out else "unknown"

        elif args.claim == "tests-pass":
            PROFILES = {
                "python-full": ["python", "-m", "pytest"],
                "npm-full": ["npm", "test"]
            }
            if args.profile not in PROFILES:
                print(f"Unknown test profile '{args.profile}'.", file=sys.stderr)
                sys.exit(1)
                
            cmd = PROFILES[args.profile]
            evidence["command"] = " ".join(cmd)
            
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.abspath(args.repo_path))
            evidence["exit_code"] = res.returncode
            
        elif args.claim == "running":
            evidence["pid"] = args.pid
            evidence["expected_bin_hash"] = args.expected_bin_hash
            try:
                proc = psutil.Process(args.pid)
                evidence["executable_path"] = proc.exe()
                evidence["actual_bin_hash"] = get_file_sha256(evidence["executable_path"])
            except Exception:
                pass
                
        elif args.claim == "endpoint-working":
            evidence["url"] = args.url
            evidence["expected_status"] = args.expected_status
            evidence["expected_content"] = args.expected_content
            try:
                resp = requests.get(args.url, timeout=10)
                evidence["actual_status"] = resp.status_code
                evidence["content_found"] = (args.expected_content in resp.text) if args.expected_content else False
            except Exception:
                evidence["actual_status"] = 0
                evidence["content_found"] = False

        payload = {
            "claim": args.claim,
            "evidence": evidence
        }
        
        try:
            resp = requests.post(SERVICE_URL, json=payload, timeout=15)
            record = resp.json()
            print(json.dumps(record, indent=2))
            
            if resp.status_code != 200 or record.get("status") != "PASS":
                sys.exit(1)
            sys.exit(0)
            
        except requests.exceptions.RequestException as e:
            print(f"VERIFICATION FAILED: Could not connect to protected service at {SERVICE_URL}. Is it running?", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
