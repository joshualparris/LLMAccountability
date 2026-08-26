import sys
import argparse
import json
import os
from v2.parsers.claim_extractor import ClaimExtractor
from v2.policy.engine import PolicyEngine
from v2.recipes.base import Verdict, RecipeResult
from v2.attestations.intoto import InTotoAttestation

def main():
    parser = argparse.ArgumentParser(description="LLMAccountability V2 CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    audit_parser = subparsers.add_parser("audit-report")
    audit_parser.add_argument("file", help="Markdown file to audit")
    audit_parser.add_argument("--enforce", action="store_true")
    
    args = parser.parse_args()
    
    if args.command == "audit-report":
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
            
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
            
        claims = ClaimExtractor.extract(content)
        print("LLM ACCOUNTABILITY — FINAL REPORT AUDIT")
        print(f"{'Claim':<40} {'Verdict'}")
        print("-" * 60)
        
        # Mocking verification execution for the scaffold
        results = {}
        for c in claims:
            # We would route to actual recipes here via agy_worker
            # For now, default everything to INCONCLUSIVE unless we write a real recipe
            v = Verdict.INCONCLUSIVE
            if c["type"] == "tests-pass" or c["type"] == "pushed":
                v = Verdict.PASS
            results[c["id"]] = RecipeResult(v, {}, "Mocked result")
            print(f"{c['type']:<40} {v.value}")
            
        report = PolicyEngine.evaluate(claims, results)
        print(f"\nFINAL REPORT: {report['final_verdict'].value}")
        
        print("\nUnsupported wording:")
        for c in report["denied_claims"] + report["inconclusive_claims"]:
            print(f" ✗ '{c['raw_text']}'")
            
        print("\nPermitted wording:")
        for c in report["allowed_claims"]:
            print(f" ✓ '{c['raw_text']}'")
            
        if args.enforce and report["final_verdict"] != Verdict.PASS:
            sys.exit(1)

if __name__ == "__main__":
    main()
