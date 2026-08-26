import requests
from typing import Dict, Any
from v2.recipes.base import BaseRecipe, Verdict, RecipeResult

class TestsPassRecipe(BaseRecipe):
    def verify(self, claim: Dict[str, Any], context: Dict[str, Any]) -> RecipeResult:
        repo_path = context.get("repo_path", ".")
        profile = context.get("profile", "python-full")
        
        # Route through the Protected Execution Broker
        try:
            resp = requests.post(
                "http://127.0.0.1:8124/execute",
                json={"claim": "tests-pass", "repo_path": repo_path, "profile": profile},
                timeout=60
            )
            
            if resp.status_code != 200:
                return RecipeResult(Verdict.INCONCLUSIVE, {"error": resp.text}, "Broker execution failed")
                
            data = resp.json()
            evidence = data.get("evidence", {})
            signature = data.get("signature", "")
            
            exit_code = evidence.get("exit_code")
            
            if exit_code is None:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, "No exit code reported by runner")
                
            evidence["broker_signature"] = signature
            
            if exit_code == 0:
                return RecipeResult(Verdict.PASS, evidence, "Test command returned exit code 0")
            else:
                return RecipeResult(Verdict.FAIL, evidence, f"Test command failed with exit code {exit_code}")
                
        except requests.exceptions.RequestException as e:
            return RecipeResult(Verdict.INCONCLUSIVE, {"error": str(e)}, "Failed to connect to Broker")
