"""
Unit tests for RSA key management (P0.1)
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from jose import jwt, JWTError

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto import RSAKeyManager


class TestRSAKeyManager:
    """Tests for RSA key manager"""
    
    @pytest.fixture
    def temp_keys_dir(self):
        """Create temporary directory for keys"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def key_manager(self, temp_keys_dir):
        """Create key manager with temp directory"""
        return RSAKeyManager(keys_dir=temp_keys_dir)
    
    def test_generate_key_pair(self, key_manager, temp_keys_dir):
        """Test generating a new RSA key pair"""
        kid = key_manager.generate_key_pair("test-key")
        
        assert kid == "test-key"
        assert kid in key_manager.keys
        assert key_manager.keys[kid]["active"] is True
        
        # Check files exist
        keys_path = Path(temp_keys_dir)
        assert (keys_path / "test-key_private.pem").exists()
        assert (keys_path / "test-key_public.pem").exists()
        assert (keys_path / "test-key_metadata.json").exists()
    
    def test_generate_key_pair_auto_kid(self, key_manager):
        """Test generating key with auto-generated kid"""
        kid = key_manager.generate_key_pair()
        
        assert kid.startswith("key-")
        assert kid in key_manager.keys
    
    def test_sign_token(self, key_manager):
        """Test signing a JWT token"""
        kid = key_manager.generate_key_pair("signing-key")
        
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow()
        }
        
        token = key_manager.sign_token(payload, kid)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token has kid in header
        header = jwt.get_unverified_header(token)
        assert header["kid"] == kid
        assert header["alg"] == "RS256"
    
    def test_verify_token(self, key_manager):
        """Test verifying a JWT token"""
        kid = key_manager.generate_key_pair("verify-key")
        
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
            "roles": ["user"]
        }
        
        token = key_manager.sign_token(payload, kid)
        
        # Verify token
        decoded = key_manager.verify_token(token)
        
        assert decoded["sub"] == "user123"
        assert decoded["roles"] == ["user"]
    
    def test_verify_token_invalid(self, key_manager):
        """Test verifying an invalid token"""
        key_manager.generate_key_pair("test-key")
        
        with pytest.raises(JWTError):
            key_manager.verify_token("invalid.token.here")
    
    def test_verify_token_expired(self, key_manager):
        """Test verifying an expired token"""
        kid = key_manager.generate_key_pair("expired-key")
        
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() - timedelta(hours=1),  # Expired
            "iat": datetime.utcnow() - timedelta(hours=2)
        }
        
        token = key_manager.sign_token(payload, kid)
        
        with pytest.raises(JWTError):
            key_manager.verify_token(token)
    
    def test_rotate_keys(self, key_manager):
        """Test key rotation"""
        # Generate initial key
        old_kid = key_manager.generate_key_pair("old-key")
        assert key_manager.current_kid == old_kid
        
        # Rotate to new key
        new_kid = key_manager.rotate_keys()
        
        assert new_kid != old_kid
        assert key_manager.current_kid == new_kid
        assert new_kid in key_manager.keys
        assert old_kid in key_manager.keys  # Old key still exists
    
    def test_deactivate_key(self, key_manager):
        """Test deactivating a key"""
        kid = key_manager.generate_key_pair("deactivate-test")
        
        assert key_manager.keys[kid]["active"] is True
        
        key_manager.deactivate_key(kid)
        
        assert key_manager.keys[kid]["active"] is False
    
    def test_get_jwks(self, key_manager):
        """Test generating JWKS"""
        key_manager.generate_key_pair("jwks-key-1")
        key_manager.generate_key_pair("jwks-key-2")
        
        jwks = key_manager.get_jwks()
        
        assert "keys" in jwks
        assert len(jwks["keys"]) == 2
        
        # Check key format
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key
    
    def test_get_jwks_only_active_keys(self, key_manager):
        """Test JWKS only includes active keys"""
        key_manager.generate_key_pair("active-key")
        inactive_kid = key_manager.generate_key_pair("inactive-key")
        
        key_manager.deactivate_key(inactive_kid)
        
        jwks = key_manager.get_jwks()
        
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == "active-key"
    
    def test_load_keys_on_init(self, temp_keys_dir):
        """Test loading existing keys on initialization"""
        # Create first manager and generate keys
        manager1 = RSAKeyManager(keys_dir=temp_keys_dir)
        kid1 = manager1.generate_key_pair("persistent-key")
        
        # Create second manager - should load existing keys
        manager2 = RSAKeyManager(keys_dir=temp_keys_dir)
        
        assert kid1 in manager2.keys
        assert manager2.current_kid == kid1
    
    def test_sign_with_current_key(self, key_manager):
        """Test signing with current key (no kid specified)"""
        key_manager.generate_key_pair("current-key")
        
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        
        token = key_manager.sign_token(payload)  # No kid specified
        
        header = jwt.get_unverified_header(token)
        assert header["kid"] == key_manager.current_kid
    
    def test_verify_token_with_rotated_keys(self, key_manager):
        """Test verifying tokens after key rotation"""
        # Generate and sign with first key
        old_kid = key_manager.generate_key_pair("old-key")
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow()
        }
        old_token = key_manager.sign_token(payload, old_kid)
        
        # Rotate keys
        new_kid = key_manager.rotate_keys()
        
        # Sign with new key
        new_token = key_manager.sign_token(payload, new_kid)
        
        # Both tokens should verify
        old_decoded = key_manager.verify_token(old_token)
        new_decoded = key_manager.verify_token(new_token)
        
        assert old_decoded["sub"] == "user123"
        assert new_decoded["sub"] == "user123"
    
    def test_list_keys(self, key_manager):
        """Test listing all keys"""
        key_manager.generate_key_pair("key-1")
        key_manager.generate_key_pair("key-2")
        
        keys = key_manager.list_keys()
        
        assert len(keys) == 2
        assert "key-1" in keys
        assert "key-2" in keys
        assert "created_at" in keys["key-1"]
        assert "active" in keys["key-1"]
    
    def test_get_current_kid(self, key_manager):
        """Test getting current signing key ID"""
        assert key_manager.get_current_kid() is None
        
        kid = key_manager.generate_key_pair("current")
        
        assert key_manager.get_current_kid() == kid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
