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
            
            if "diagnostic_reason" in evidence:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, f"Diagnostic failure: {evidence['diagnostic_reason']}")
                
            local_sha_ev = evidence.get("git_rev_parse_head", {})
            remote_sha_ev = evidence.get("git_rev_parse_upstream", {})
            ls_remote_ev = evidence.get("git_ls_remote", {})
            
            def get_sha(ev):
                if ev and ev.get("exit_code") == 0 and ev.get("stdout_snippet"):
                    return ev["stdout_snippet"].strip().split()[0]
                return None
                
            local = get_sha(local_sha_ev)
            remote = get_sha(remote_sha_ev)
            ls_remote = get_sha(ls_remote_ev)
            
            # Prerequisite failures are INCONCLUSIVE
            for cmd_key in ["git_fetch", "git_status", "git_rev_parse_branch", "git_rev_parse_head", "git_rev_parse_upstream"]:
                ev = evidence.get(cmd_key)
                if ev:
                    if ev.get("spawn_error") or ev.get("exit_code") != 0:
                        return RecipeResult(Verdict.INCONCLUSIVE, evidence, f"Prerequisite {cmd_key} failed")
            
            # If ls_remote was attempted and failed to execute/spawn/network, that is INCONCLUSIVE
            # (If it failed with exit code 0 but no output, get_sha returns None)
            if evidence.get("git_ls_remote") and evidence["git_ls_remote"].get("exit_code") != 0:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, "Prerequisite git_ls_remote failed")
            
            if not local or not remote or not ls_remote:
                return RecipeResult(Verdict.INCONCLUSIVE, evidence, "Unable to establish complete Git SHAs")
                
            if local == remote and local == ls_remote:
                return RecipeResult(Verdict.PASS, evidence, "Local branch perfectly synced with remote")
            else:
                return RecipeResult(Verdict.FAIL, evidence, f"Unsynced: local={local}, remote={remote}, ls_remote={ls_remote}")
                
        except requests.exceptions.RequestException as e:
            return RecipeResult(Verdict.INCONCLUSIVE, {"error": str(e)}, "Failed to connect to Broker")