import requests
from typing import Dict, Any
from v2.recipes.base import BaseRecipe, Verdict, RecipeResult

class TestsPassRecipe(BaseRecipe):
    def verify(self, claim: Dict[str, Any], context: Dict[str, Any]) -> RecipeResult:
        repo_path = context.get("repo_path", ".")
        profile = context.get("profile", "python-full")
        
        # Route through the SYSTEM Notary
        try:
            resp = requests.post(
                "http://127.0.0.1:8123/v2/execute",
                json={"claim": "tests-pass", "repo_path": repo_path, "profile": profile},
                timeout=60
            )
            
            if resp.status_code != 200:
                return RecipeResult(Verdict.INCONCLUSIVE, {"error": resp.text}, "Notary execution failed")
                
            data = resp.json()
            evidence = data.get("evidence", {})
            authenticated = data.get("authenticated", False)
            
            if not authenticated:
                return RecipeResult(Verdict.FAIL, evidence, "Evidence rejected by SYSTEM notary")
            
            if "diagnostic_reason" in evidence:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, f"Diagnostic failure: {evidence['diagnostic_reason']}")
                
            if "spawn_error" in evidence:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, f"Process spawn error: {evidence['spawn_error']}")
            
            exit_code = evidence.get("exit_code")
            
            if exit_code is None or exit_code == -1:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, "No valid exit code reported by runner")
                
            if exit_code == 0:
                return RecipeResult(Verdict.PASS, evidence, "Test command returned exit code 0")
            else:
                return RecipeResult(Verdict.FAIL, evidence, f"Test command failed with exit code {exit_code}")
                
        except requests.exceptions.RequestException as e:
            return RecipeResult(Verdict.INCONCLUSIVE, {"error": str(e)}, "Failed to connect to Broker")