"""
RSA key management for JWT signing (P0.1)

Handles RSA key pair generation, loading, and rotation.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jose import jwt, JWTError
import json
import threading
import time
import schedule

logger = logging.getLogger(__name__)


class RSAKeyManager:
    """
    Manages RSA key pairs for JWT signing with rotation support.
    """
    
    def __init__(
        self,
        keys_dir: str = "/app/keys",
        rotation_interval_hours: int = 24  # 24 hours for daily rotation
    ):
        """
        Initialize RSA key manager.
        
        Args:
            keys_dir: Directory containing RSA key files
            rotation_interval_hours: Hours between key rotations (24 for daily)
        """
        self.keys_dir = Path(keys_dir)
        self.rotation_interval = timedelta(hours=rotation_interval_hours)
        self.keys: Dict[str, Dict] = {}
        self.current_kid: Optional[str] = None
        self._rotation_thread: Optional[threading.Thread] = None
        self._stop_rotation = threading.Event()
        
        # Ensure keys directory exists
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing keys
        self._load_keys()
        
        # Start rotation scheduler
        self._start_rotation_scheduler()
    
    def _load_keys(self):
        """Load all RSA key pairs from keys directory"""
        logger.info(f"Loading RSA keys from {self.keys_dir}")
        
        # Look for private key files
        for key_file in self.keys_dir.glob("*.pem"):
            if key_file.stem.endswith("_private"):
                kid = key_file.stem.replace("_private", "")
                try:
                    private_key, public_key = self._load_key_pair(kid)
                    
                    # Load metadata if exists
                    metadata_file = self.keys_dir / f"{kid}_metadata.json"
                    if metadata_file.exists():
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                    else:
                        metadata = {
                            "created_at": datetime.utcnow().isoformat(),
                            "active": True
                        }
                    
                    self.keys[kid] = {
                        "kid": kid,
                        "private_key": private_key,
                        "public_key": public_key,
                        "created_at": metadata.get("created_at"),
                        "active": metadata.get("active", True)
                    }
                    
                    logger.info(f"Loaded key: {kid} (active: {metadata.get('active', True)})")
                    
                except Exception as e:
                    logger.error(f"Failed to load key {kid}: {e}")
        
        # Set current key (most recent active key)
        if self.keys:
            active_keys = [k for k, v in self.keys.items() if v["active"]]
            if active_keys:
                self.current_kid = max(active_keys)
                logger.info(f"Current signing key: {self.current_kid}")
            else:
                logger.warning("No active keys found")
        else:
            logger.warning("No keys loaded, will need to generate")
    
    def _start_rotation_scheduler(self):
        """Start the background rotation scheduler"""
        if self._rotation_thread is None or not self._rotation_thread.is_alive():
            self._stop_rotation.clear()
            self._rotation_thread = threading.Thread(target=self._rotation_worker, daemon=True)
            self._rotation_thread.start()
            logger.info("Key rotation scheduler started")
    
    def _rotation_worker(self):
        """Background worker for scheduled key rotation"""
        # Schedule daily rotation at 2 AM UTC
        schedule.every().day.at("02:00").do(self._scheduled_rotation)
        
        while not self._stop_rotation.is_set():
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def _scheduled_rotation(self):
        """Scheduled key rotation task"""
        try:
            logger.info("Starting scheduled key rotation")
            new_kid = self.rotate_keys()
            
            # Clean up old keys (older than 7 days and not current)
            self._cleanup_old_keys()
            
            logger.info(f"Scheduled rotation completed: new kid={new_kid}")
        except Exception as e:
            logger.error(f"Scheduled key rotation failed: {e}")
    
    def _cleanup_old_keys(self):
        """Remove keys older than grace period (7 days) that are not current"""
        grace_period = timedelta(days=7)
        cutoff_time = datetime.utcnow() - grace_period
        
        for kid in list(self.keys.keys()):
            if kid == self.current_kid:
                continue  # Never remove current key
            
            key_info = self.keys[kid]
            created_at = datetime.fromisoformat(key_info["created_at"])
            
            if created_at < cutoff_time and not key_info["active"]:
                logger.info(f"Removing old key: {kid}")
                self._remove_key_files(kid)
                del self.keys[kid]
    
    def _remove_key_files(self, kid: str):
        """Remove all files associated with a key"""
        files_to_remove = [
            self.keys_dir / f"{kid}_private.pem",
            self.keys_dir / f"{kid}_public.pem",
            self.keys_dir / f"{kid}_metadata.json"
        ]
        
        for file_path in files_to_remove:
            if file_path.exists():
                file_path.unlink()
    
    def stop_rotation(self):
        """Stop the rotation scheduler"""
        self._stop_rotation.set()
        if self._rotation_thread and self._rotation_thread.is_alive():
            self._rotation_thread.join(timeout=5)
        logger.info("Key rotation scheduler stopped")
    
    def _load_key_pair(self, kid: str) -> Tuple:
        """Load a specific key pair"""
        private_key_path = self.keys_dir / f"{kid}_private.pem"
        public_key_path = self.keys_dir / f"{kid}_public.pem"
        
        # Load private key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        return private_key, public_key
    
    def generate_key_pair(self, kid: Optional[str] = None) -> str:
        """
        Generate a new RSA key pair.
        
        Args:
            kid: Key ID (defaults to timestamp-based ID)
        
        Returns:
            Key ID of generated key
        """
        if kid is None:
            kid = f"key-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        logger.info(f"Generating new RSA key pair: {kid}")
        
        # Generate RSA key pair (2048-bit)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_path = self.keys_dir / f"{kid}_private.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(private_key_path, 0o600)  # Restrict permissions
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_path = self.keys_dir / f"{kid}_public.pem"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        # Save metadata
        metadata = {
            "created_at": datetime.utcnow().isoformat(),
            "active": True
        }
        metadata_path = self.keys_dir / f"{kid}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Add to keys dict
        self.keys[kid] = {
            "kid": kid,
            "private_key": private_key,
            "public_key": public_key,
            "created_at": metadata["created_at"],
            "active": True
        }
        
        # Set as current if no current key
        if self.current_kid is None:
            self.current_kid = kid
            logger.info(f"Set {kid} as current signing key")
        
        logger.info(f"Generated and saved key pair: {kid}")
        return kid
    
    def rotate_keys(self) -> str:
        """
        Rotate to a new key pair.
        
        Generates a new key and sets it as current.
        Old keys remain valid for grace period.
        
        Returns:
            Key ID of new key
        """
        logger.info("Rotating RSA keys")
        
        # Generate new key
        new_kid = self.generate_key_pair()
        
        # Set as current
        old_kid = self.current_kid
        self.current_kid = new_kid
        
        logger.info(f"Rotated from {old_kid} to {new_kid}")
        return new_kid
    
    def deactivate_key(self, kid: str):
        """Deactivate a key (will no longer be used for signing)"""
        if kid in self.keys:
            self.keys[kid]["active"] = False
            
            # Update metadata file
            metadata_path = self.keys_dir / f"{kid}_metadata.json"
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                metadata["active"] = False
                metadata["deactivated_at"] = datetime.utcnow().isoformat()
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
            
            logger.info(f"Deactivated key: {kid}")
    
    def sign_token(self, payload: Dict, kid: Optional[str] = None) -> str:
        """
        Sign a JWT token with RSA private key.
        
        Args:
            payload: Token payload
            kid: Key ID to use (defaults to current key)
        
        Returns:
            Signed JWT token
        """
        if kid is None:
            kid = self.current_kid
        
        if kid is None or kid not in self.keys:
            raise ValueError(f"Key {kid} not found")
        
        key_info = self.keys[kid]
        if not key_info["active"]:
            logger.warning(f"Signing with inactive key: {kid}")
        
        # Add kid to header
        headers = {"kid": kid}
        
        # Convert private key to PEM for jose
        private_pem = key_info["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Sign token
        token = jwt.encode(
            payload,
            private_pem,
            algorithm="RS256",
            headers=headers
        )
        
        return token
    
    def verify_token(self, token: str) -> Dict:
        """
        Verify a JWT token with RSA public key.
        
        Args:
            token: JWT token to verify
        
        Returns:
            Decoded token payload
        
        Raises:
            JWTError: If token is invalid
        """
        # Decode header to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if kid is None:
            raise JWTError("Token missing kid in header")
        
        if kid not in self.keys:
            raise JWTError(f"Unknown key ID: {kid}")
        
        # Get public key
        key_info = self.keys[kid]
        public_pem = key_info["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Verify token
        payload = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"]
        )
        
        return payload
    
    def get_jwks(self) -> Dict:
        """
        Get JWKS (JSON Web Key Set) for public key distribution.
        
        Returns:
            JWKS dictionary
        """
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        import base64
        
        keys = []
        for kid, key_info in self.keys.items():
            if not key_info["active"]:
                continue  # Only include active keys in JWKS
            
            public_key = key_info["public_key"]
            public_numbers = public_key.public_numbers()
            
            # Convert to base64url encoding
            def int_to_base64url(num):
                num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
                return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')
            
            keys.append({
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e)
            })
        
        return {"keys": keys}
    
    def get_current_kid(self) -> Optional[str]:
        """Get current signing key ID"""
        return self.current_kid
    
    def list_keys(self) -> Dict[str, Dict]:
        """List all keys with metadata"""
        return {
            kid: {
                "kid": kid,
                "created_at": info["created_at"],
                "active": info["active"]
            }
            for kid, info in self.keys.items()
        }


# Global key manager instance
_key_manager: Optional[RSAKeyManager] = None


def get_key_manager() -> RSAKeyManager:
    """Get the global RSA key manager instance"""
    global _key_manager
    if _key_manager is None:
        keys_dir = os.getenv("UNISON_AUTH_KEYS_DIR", "/app/keys")
        rotation_hours = int(os.getenv("UNISON_AUTH_KEY_ROTATION_HOURS", "24"))  # Daily rotation
        _key_manager = RSAKeyManager(keys_dir, rotation_hours)
        
        # Generate initial key if none exist
        if not _key_manager.keys:
            logger.info("No keys found, generating initial key pair")
            _key_manager.generate_key_pair("primary-2025-11")
    
    return _key_manager
