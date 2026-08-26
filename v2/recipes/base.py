from enum import Enum
from typing import Dict, Any, Optional

class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    PARTIAL = "PARTIAL" # Mapped to INCONCLUSIVE by policy

class RecipeResult:
    def __init__(self, verdict: Verdict, evidence: Dict[str, Any], reason: str = ""):
        self.verdict = verdict
        self.evidence = evidence
        self.reason = reason

class BaseRecipe:
    @property
    def name(self) -> str:
        return self.__class__.__name__

    def verify(self, claim: Dict[str, Any], context: Dict[str, Any]) -> RecipeResult:
        raise NotImplementedError
