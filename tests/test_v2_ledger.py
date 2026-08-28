import os
import json
import pytest
from unittest.mock import patch
import agy_service

def test_ledger_tamper_detection(tmp_path):
    ledger_path = tmp_path / "protected_ledger.jsonl"
    
    with patch("agy_service.LEDGER_PATH", str(ledger_path)):
        with patch("agy_service.serialization.load_pem_public_key") as mock_load_key:
            # Create a dummy public key file
            pub_key_path = tmp_path / "public.pem"
            pub_key_path.write_bytes(b"dummy")
            
            with patch("agy_service.PUB_KEY_PATH", str(pub_key_path)):
                # Mock the public key verify to always pass
                mock_key = mock_load_key.return_value
                mock_key.verify.return_value = None
                
                # Write valid initial state
                valid_record = {
                    "timestamp": "2026-08-28T00:00:00.000000+00:00",
                    "claim": "tests-pass",
                    "status": "PASS",
                    "evidence": {},
                    "previous_hash": "0" * 64
                }
                
                canonical = json.dumps(valid_record, sort_keys=True)
                import hashlib
                calc_hash = hashlib.sha256((valid_record["previous_hash"] + canonical).encode("utf-8")).hexdigest()
                valid_record["hash"] = calc_hash
                valid_record["certificate_id"] = f"AGY-20260828-{calc_hash[:8]}"
                valid_record["signature_ed25519"] = "dummy_sig"
                
                agy_service.append_ledger(valid_record)
                
                # Verify it passes validation
                agy_service.validate_ledger()
                
                # Tamper it!
                lines = ledger_path.read_text().splitlines()
                tampered = json.loads(lines[0])
                tampered["status"] = "FAIL"
                ledger_path.write_text(json.dumps(tampered) + "\n")
                
                # Now validation should fail
                with pytest.raises(RuntimeError, match="Ledger tampered"):
                    agy_service.validate_ledger()
