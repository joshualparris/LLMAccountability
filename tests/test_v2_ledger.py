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

def test_ledger_real_crypto(tmp_path):
    import json
    import hashlib
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import agy_service

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    pub_path = tmp_path / "public.pem"
    pub_path.write_bytes(pub_pem)
    ledger_path = tmp_path / "protected_ledger.jsonl"
    
    with patch("agy_service.LEDGER_PATH", str(ledger_path)):
        with patch("agy_service.PUB_KEY_PATH", str(pub_path)):
            valid_record = {
                "timestamp": "2026-08-28T00:00:00.000000+00:00",
                "claim": "tests-pass",
                "status": "PASS",
                "evidence": {},
                "previous_hash": "0" * 64
            }
            canonical = json.dumps(valid_record, sort_keys=True)
            calc_hash = hashlib.sha256((valid_record["previous_hash"] + canonical).encode("utf-8")).hexdigest()
            valid_record["hash"] = calc_hash
            valid_record["certificate_id"] = f"AGY-20260828-{calc_hash[:8]}"
            
            canon2 = json.dumps(valid_record, sort_keys=True).encode("utf-8")
            sig = priv.sign(canon2)
            valid_record["signature_ed25519"] = base64.b64encode(sig).decode("utf-8")
            
            agy_service.append_ledger(valid_record)
            
            # 1. correctly signed record validates
            agy_service.validate_ledger()
            
            # 2. modified record fails hash validation
            lines = ledger_path.read_text().splitlines()
            r1 = json.loads(lines[0])
            r1["status"] = "FAIL"
            ledger_path.write_text(json.dumps(r1) + "\n")
            with pytest.raises(RuntimeError, match="Ledger tampered"):
                agy_service.validate_ledger()
                
            # 3. unchanged hash fields with invalid signature fails signature validation
            r2 = json.loads(lines[0])
            bad_priv = ed25519.Ed25519PrivateKey.generate()
            bad_sig = bad_priv.sign(calc_hash.encode("utf-8"))
            r2["signature_ed25519"] = base64.b64encode(bad_sig).decode("utf-8")
            ledger_path.write_text(json.dumps(r2) + "\n")
            with pytest.raises(RuntimeError, match="Invalid cryptographic signature"):
                agy_service.validate_ledger()
                
            # 4. missing signature fails
            r3 = json.loads(lines[0])
            del r3["signature_ed25519"]
            ledger_path.write_text(json.dumps(r3) + "\n")
            with pytest.raises(RuntimeError, match="Missing signature"):
                agy_service.validate_ledger()
                
            # 5. correct signature, but wrong public key
            r4 = json.loads(lines[0])
            wrong_priv = ed25519.Ed25519PrivateKey.generate()
            wrong_pub = wrong_priv.public_key()
            wrong_pub_pem = wrong_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            wrong_pub_path = tmp_path / "wrong_public.pem"
            wrong_pub_path.write_bytes(wrong_pub_pem)
            with patch("agy_service.PUB_KEY_PATH", str(wrong_pub_path)):
                ledger_path.write_text(json.dumps(r4) + "\n")
                with pytest.raises(RuntimeError, match="Invalid cryptographic signature"):
                    agy_service.validate_ledger()

def test_service_level_tamper_fails_closed(tmp_path):
    import json
    import hashlib
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import agy_service
    from fastapi.testclient import TestClient

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    pub_path = tmp_path / "public.pem"
    priv_path = tmp_path / "private.pem"
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pub_path.write_bytes(pub_pem)
    priv_path.write_bytes(priv_pem)
    
    ledger_path = tmp_path / "protected_ledger.jsonl"
    
    from unittest.mock import patch
    with patch("agy_service.LEDGER_PATH", str(ledger_path)), \
         patch("agy_service.PUB_KEY_PATH", str(pub_path)), \
         patch("agy_service.private_key", priv), \
         patch("agy_service.public_key", pub, create=True):
         
        # Create initial valid record
        valid_record = {
            "timestamp": "2026-08-28T00:00:00.000000+00:00",
            "claim": "tests-pass",
            "status": "PASS",
            "evidence": {},
            "previous_hash": "0" * 64
        }
        canonical = json.dumps(valid_record, sort_keys=True)
        calc_hash = hashlib.sha256((valid_record["previous_hash"] + canonical).encode("utf-8")).hexdigest()
        valid_record["hash"] = calc_hash
        valid_record["certificate_id"] = f"AGY-20260828-{calc_hash[:8]}"
        
        canon2 = json.dumps(valid_record, sort_keys=True).encode("utf-8")
        sig = priv.sign(canon2)
        valid_record["signature_ed25519"] = base64.b64encode(sig).decode("utf-8")
        
        agy_service.append_ledger(valid_record)
        
        # Tamper it!
        lines = ledger_path.read_text().splitlines()
        r1 = json.loads(lines[0])
        r1["status"] = "FAIL"
        ledger_path.write_text(json.dumps(r1) + "\\n")
        
        # Call certification path!
        client = TestClient(agy_service.app)
        resp = client.post("/certify", json={"job_id": "test", "claim": "tests-pass", "evidence": {"foo": "bar"}})
        
        # Certification refused
        assert resp.status_code == 500
        assert "Audit log corrupt" in resp.json()["detail"] or "Ledger tampered" in resp.json()["detail"] or "Invalid cryptographic signature" in resp.json()["detail"]
        
        # No new valid certificate appended
        lines_after = ledger_path.read_text().splitlines()
        assert len(lines_after) == 1

