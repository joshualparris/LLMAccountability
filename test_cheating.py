import os
import json
import hashlib
import sys
import subprocess

AUDIT_LOG = os.path.abspath("agy_verification_audit.jsonl")

def test_hash_chain():
    print("Testing hash chain integrity...")
    if not os.path.exists(AUDIT_LOG):
        print("No audit log found.")
        return

    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        print("Audit log is empty.")
        return

    prev_hash = "0" * 64
    for i, line in enumerate(lines):
        record = json.loads(line)
        expected_hash = record.get("hash")
        
        # Reconstruct the record to calculate its hash
        temp_record = {
            "timestamp": record["timestamp"],
            "claim": record["claim"],
            "status": record["status"],
            "evidence": record["evidence"]
        }
        if "error" in record:
            temp_record["error"] = record["error"]
            
        temp_record["previous_hash"] = prev_hash
        
        canonical_json = json.dumps(temp_record, sort_keys=True)
        calculated_hash = hashlib.sha256((prev_hash + canonical_json).encode("utf-8")).hexdigest()
        
        if calculated_hash != expected_hash:
            print(f"FAIL: Hash mismatch at line {i+1}!")
            print(f"Expected: {expected_hash}")
            print(f"Calculated: {calculated_hash}")
            sys.exit(1)
            
        prev_hash = expected_hash
        
    print("PASS: Hash chain is fully intact and cryptographically sound.")

def test_tamper_detection():
    print("Testing tamper detection...")
    
    # Run the verifier once to create a valid record
    subprocess.run(["python", "agy_verifier.py", "certify", "--claim", "running", "--pid", "999999"], capture_output=True)
    
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    # Tamper with the last record
    last_record = json.loads(lines[-1])
    last_record["status"] = "PASS" # Maliciously change FAIL to PASS
    lines[-1] = json.dumps(last_record) + "\n"
    
    with open(AUDIT_LOG, "w", encoding="utf-8") as f:
        f.writelines(lines)
        
    # Now run the integrity check again. It should fail!
    print("Running integrity check on tampered log...")
    try:
        test_hash_chain()
        print("FATAL: Tamper detection failed to catch the modification!")
        sys.exit(1)
    except SystemExit as e:
        if e.code == 1:
            print("PASS: Tamper detection successfully caught the modification.")
        else:
            raise

if __name__ == "__main__":
    test_hash_chain()
    test_tamper_detection()
