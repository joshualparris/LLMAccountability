import sys
import argparse
import json
import os
import base64
from v2.parsers.claim_extractor import ClaimExtractor
from v2.policy.engine import PolicyEngine
from v2.recipes.base import Verdict, RecipeResult
from v2.attestations.intoto import InTotoAttestation

from v2.recipes.git import GitPushRecipe
from v2.recipes.tests import TestsPassRecipe

def main():
    parser = argparse.ArgumentParser(description="LLMAccountability V2 CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    audit_parser = subparsers.add_parser("audit-report")
    audit_parser.add_argument("file", help="Markdown file to audit")
    audit_parser.add_argument("--enforce", action="store_true")
    audit_parser.add_argument("--repo-path", default=".", help="Repository path to verify against")
    audit_parser.add_argument("--test-profile", default="python-full", help="Test profile to run")
    
    args = parser.parse_args()
    
    if args.command == "audit-report":
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
            
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
            
        claims = ClaimExtractor.extract(content, report_id=args.file)
        print("LLM ACCOUNTABILITY — FINAL REPORT AUDIT")
        print(f"{'Claim':<40} {'Verdict'}")
        print("-" * 60)
        
        import requests
        
        # Request a signed attestation from the SYSTEM Notary
        try:
            resp = requests.post(
                "http://127.0.0.1:8123/v2/attest",
                json={
                    "claims": claims,
                    "context": {"repo_path": args.repo_path, "profile": args.test_profile},
                    "subject_name": args.file,
                    "subject_digest": "sha256:dummy"
                },
                timeout=120
            )
            
            if resp.status_code != 200:
                print(f"Notary failed to attest: {resp.text}")
                sys.exit(1)
                
            env = resp.json()
            payload = json.loads(base64.b64decode(env["payload"]))
            policy = payload["predicate"]["policy_evaluation"]
            results = payload["predicate"]["results"]
            
            for c in claims:
                print(f"{c['type']:<40} {results[c['id']]['verdict']}")
                
            print(f"\\nFINAL REPORT: {policy['final_verdict']}")
            
            print("\\nUnsupported wording:")
            for c in policy["denied"]:
                print(f" ✗ '{c}'")
                
            print("\\nPermitted wording:")
            for c in policy["allowed"]:
                print(f" ✓ '{c}'")
                
            if args.enforce and policy["final_verdict"] != "PASS":
                sys.exit(1)
                
        except Exception as e:
            print(f"Error connecting to Notary: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
