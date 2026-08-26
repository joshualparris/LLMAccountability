import re
import uuid
from typing import List, Dict, Any

CLAIM_PATTERNS = {
    "tests-pass": [r"(?i)tests pass", r"(?i)all tests passed", r"(?i)automated tests passed"],
    "pushed": [r"(?i)pushed (?:to|v\d+)", r"(?i)push to main"],
    "no-secrets": [r"(?i)no secrets were committed", r"(?i)secure"],
    "fully-complete": [r"(?i)fully complete", r"(?i)production ready", r"(?i)every requirement is implemented"]
}

class ClaimExtractor:
    @staticmethod
    def extract(text: str) -> List[Dict[str, Any]]:
        claims = []
        for claim_type, patterns in CLAIM_PATTERNS.items():
            for p in patterns:
                if re.search(p, text):
                    claims.append({
                        "id": str(uuid.uuid4()),
                        "type": claim_type,
                        "raw_text": re.search(p, text).group(0)
                    })
                    break # Avoid duplicating the same claim type if multiple patterns match
        return claims
