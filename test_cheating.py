import os
import json
import hashlib
import sys
import subprocess
import tempfile
import shutil

def test_hash_chain(audit_log):
    print("Testing hash chain integrity on...", audit_log)
    if not os.path.exists(audit_log):
        print("No audit log found.")
        return

    with open(audit_log, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        print("Audit log is empty.")
        return

    prev_hash = "0" * 64
    for i, line in enumerate(lines):
        record = json.loads(line)
        expected_hash = record.get("hash")
        
        temp_record = {
            "timestamp": record["timestamp"],
            "claim": record["claim"],
            "status": record["status"],
            "evidence": record["evidence"],
            "previous_hash": prev_hash
        }
        if "error" in record:
            temp_record["error"] = record["error"]
            
        canonical_json = json.dumps(temp_record, sort_keys=True)
        calculated_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
        
        if record.get("previous_hash") != prev_hash:
            print(f"FAIL: previous_hash mismatch at line {i+1}!")
            sys.exit(1)
            
        if calculated_hash != expected_hash:
            print(f"FAIL: Hash mismatch at line {i+1}!")
            sys.exit(1)
            
        try:
            from datetime import datetime
            ts = datetime.fromisoformat(record["timestamp"])
            expected_cert_id = f"AGY-{ts.strftime('%Y%m%d')}-{calculated_hash[:8]}"
            if record.get("certificate_id") != expected_cert_id:
                print(f"FAIL: certificate_id mismatch at line {i+1}!")
                sys.exit(1)
        except ValueError:
            pass
            
        prev_hash = expected_hash
        
    print("PASS: Hash chain is fully intact.")

def test_tamper_detection():
    print("Testing fail-closed tamper detection...")
    
    with tempfile.TemporaryDirectory() as tempdir:
        test_log = os.path.join(tempdir, "agy_verification_audit.jsonl")
        
        # We need to copy agy_verifier.py to the temp dir so it can run there
        shutil.copy("agy_verifier.py", tempdir)
        
        # Run verifier to create first valid record
        subprocess.run(["python", "agy_verifier.py", "certify", "--claim", "running", "--pid", "999999"], cwd=tempdir, capture_output=True)
        
        # Run again to create second valid record
        subprocess.run(["python", "agy_verifier.py", "certify", "--claim", "running", "--pid", "999999"], cwd=tempdir, capture_output=True)
        
        with open(test_log, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # Tamper with the FIRST record
        first_record = json.loads(lines[0])
        first_record["status"] = "PASS" # Malicious edit
        lines[0] = json.dumps(first_record) + "\n"
        
        with open(test_log, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        # Now run the verifier again. It MUST fail closed before doing anything.
        print("Running verifier on tampered ledger...")
        res = subprocess.run(["python", "agy_verifier.py", "certify", "--claim", "running", "--pid", "999999"], cwd=tempdir, capture_output=True, text=True)
        
        if res.returncode == 0:
            print("FATAL: Verifier issued a certificate despite a tampered ledger!")
            print(res.stdout)
            sys.exit(1)
        elif "Ledger tampered or corrupted" in res.stderr:
            print("PASS: Verifier correctly failed closed on tampered ledger.")
        else:
            print(f"Unexpected failure: {res.stderr}")
            sys.exit(1)

if __name__ == "__main__":
    # Test production ledger just to be sure it's intact
    prod_log = os.path.abspath("agy_verification_audit.jsonl")
    if os.path.exists(prod_log):
        test_hash_chain(prod_log)
        
    test_tamper_detection()
