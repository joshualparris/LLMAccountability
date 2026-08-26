import re
import hashlib
from typing import List, Dict, Any

CLAIM_PATTERNS = {
    "tests-pass": [r"(?i)tests pass", r"(?i)all tests passed", r"(?i)automated tests passed"],
    "pushed": [r"(?i)pushed (?:to|v\\d+)", r"(?i)push to main", r"(?i)pushed (.*) to github"],
    "no-secrets": [r"(?i)no secrets were committed"],
    "security-reviewed": [r"(?i)secure", r"(?i)authentication is secure"],
    "fully-complete": [r"(?i)fully complete", r"(?i)production ready", r"(?i)every requirement is implemented"]
}

class ClaimExtractor:
    @staticmethod
    def extract(text: str, report_id: str = "default_report") -> List[Dict[str, Any]]:
        claims = []
        for claim_type, patterns in CLAIM_PATTERNS.items():
            for p in patterns:
                matches = re.finditer(p, text)
                for index, match in enumerate(matches):
                    raw_text = match.group(0)
                    
                    # Generate deterministic, stable ID
                    hasher = hashlib.sha256()
                    hasher.update(f"{report_id}:{claim_type}:{raw_text}:{index}".encode('utf-8'))
                    claim_id = hasher.hexdigest()[:16]
                    
                    claims.append({
                        "id": claim_id,
                        "type": claim_type,
                        "raw_text": raw_text
                    })
                    break # Usually we just take one claim per category per document, but we'll break inner loop to avoid redundant claims for the exact same pattern
        return claims
