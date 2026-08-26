import sys
import argparse
import json
import os
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
            
        claims = ClaimExtractor.extract(content)
        print("LLM ACCOUNTABILITY — FINAL REPORT AUDIT")
        print(f"{'Claim':<40} {'Verdict'}")
        print("-" * 60)
        
        # Route claims to actual deterministic recipes
        results = {}
        context = {"repo_path": args.repo_path, "profile": args.test_profile}
        
        for c in claims:
            if c["type"] == "pushed":
                results[c["id"]] = GitPushRecipe().verify(c, context)
            elif c["type"] == "tests-pass":
                results[c["id"]] = TestsPassRecipe().verify(c, context)
            else:
                results[c["id"]] = RecipeResult(Verdict.INCONCLUSIVE, {}, "Recipe not implemented yet")
                
            print(f"{c['type']:<40} {results[c['id']].verdict.value}")
            
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
