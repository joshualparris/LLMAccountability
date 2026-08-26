import requests
from typing import Dict, Any
from v2.recipes.base import BaseRecipe, Verdict, RecipeResult

class GitPushRecipe(BaseRecipe):
    def verify(self, claim: Dict[str, Any], context: Dict[str, Any]) -> RecipeResult:
        repo_path = context.get("repo_path", ".")
        
        # Route through the SYSTEM Notary
        try:
            resp = requests.post(
                "http://127.0.0.1:8123/v2/execute",
                json={"claim": "pushed", "repo_path": repo_path},
                timeout=30
            )
            
            if resp.status_code != 200:
                return RecipeResult(Verdict.INCONCLUSIVE, {"error": resp.text}, "Notary execution failed")
                
            data = resp.json()
            evidence = data.get("evidence", {})
            authenticated = data.get("authenticated", False)
            
            if not authenticated:
                return RecipeResult(Verdict.FAIL, evidence, "Evidence rejected by SYSTEM notary")
            
            # Simple policy check for the pushed recipe:
            # We want local head == remote head == ls-remote sha
            local = evidence.get("local_head")
            remote = evidence.get("remote_head")
            ls_remote = evidence.get("ls_remote_sha")
            
            if not local or not remote or not ls_remote:
                return RecipeResult(Verdict.FAIL, evidence, "Missing Git state")
                
            if local == remote and local == ls_remote:
                return RecipeResult(Verdict.PASS, evidence, "Local branch perfectly synced with remote")
            else:
                return RecipeResult(Verdict.FAIL, evidence, f"Unsynced: local={local}, remote={remote}, ls_remote={ls_remote}")
                
        except requests.exceptions.RequestException as e:
            return RecipeResult(Verdict.INCONCLUSIVE, {"error": str(e)}, "Failed to connect to Broker")
