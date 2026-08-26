import argparse
import sys
import json
import requests

SERVICE_URL = "http://127.0.0.1:8123/certify"

def main():
    parser = argparse.ArgumentParser(description="Antigravity RPC Client (v1.4)")
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
        payload = {
            "claim": args.claim,
            "repo_path": args.repo_path,
            "profile": args.profile,
            "pid": args.pid,
            "expected_bin_hash": args.expected_bin_hash,
            "url": args.url,
            "expected_status": args.expected_status,
            "expected_content": args.expected_content
        }
        
        # Remove None values
        payload = {k: v for k, v in payload.items() if v is not None}
        
        try:
            resp = requests.post(SERVICE_URL, json=payload, timeout=45)
            if resp.status_code != 200:
                print(f"Service returned error: {resp.text}", file=sys.stderr)
                sys.exit(1)
                
            record = resp.json()
            print(json.dumps(record, indent=2))
            
            if record.get("status") != "PASS":
                sys.exit(1)
            sys.exit(0)
            
        except requests.exceptions.RequestException as e:
            print(f"VERIFICATION FAILED: Could not connect to protected service at {SERVICE_URL}. Is it running?", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
