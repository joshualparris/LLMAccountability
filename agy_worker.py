import os
import requests
import hashlib
import hmac
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

WORKER_PORT = 8124
RUNNER_URL = "http://127.0.0.1:8125/run"
SECRET_PATH = "C:/ProgramData/AGYVerifier/worker_secret.key"

app = FastAPI(title="Antigravity Trusted Broker")

class ExecuteRequest(BaseModel):
    claim: str
    repo_path: str = "."
    profile: Optional[str] = None
    pid: Optional[int] = None
    expected_bin_hash: Optional[str] = None
    url: Optional[str] = None
    expected_status: int = 200
    expected_content: Optional[str] = None

def get_secret():
    with open(SECRET_PATH, "rb") as f:
        return f.read().strip()

def sign_response(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()

@app.post("/execute")
def execute(req: ExecuteRequest):
    evidence = {}
    try:
        # Delegate untrusted execution to the disposable AGYRunner
        payload = req.dict(exclude_none=True)
        resp = requests.post(RUNNER_URL, json=payload, timeout=45)
        
        if resp.status_code != 200:
            evidence["error"] = f"AGYRunner failed: {resp.text}"
        else:
            evidence = resp.json()
            
    except requests.exceptions.RequestException as e:
        evidence["error"] = f"Failed to communicate with AGYRunner: {e}"
        
    # We always include expected values that the notary will check, 
    # even though they are passed through from the request, so they are part of the signature.
    if req.expected_bin_hash:
        evidence["expected_bin_hash"] = req.expected_bin_hash
    if req.expected_status:
        evidence["expected_status"] = req.expected_status

    clean_evidence = {k: v for k, v in evidence.items() if v is not None}
    
    return {
        "evidence": clean_evidence,
        "signature": sign_response(clean_evidence)
    }

if __name__ == "__main__":
    print("Starting AGYWorker Broker on 8124...")
    uvicorn.run(app, host="127.0.0.1", port=WORKER_PORT, log_level="warning")
