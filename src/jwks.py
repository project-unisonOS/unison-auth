"""
JWKS (JSON Web Key Set) endpoint for public key distribution (P0.1)
"""

from fastapi import APIRouter, Response
from typing import Dict
import logging

from .crypto import get_key_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/jwks.json")
async def get_jwks(response: Response) -> Dict:
    """
    Get JWKS (JSON Web Key Set) for public key distribution.
    
    Returns public keys in JWKS format for token verification.
    Clients should cache this response and refresh periodically.
    
    Response includes Cache-Control headers for efficient caching.
    """
    try:
        key_manager = get_key_manager()
        jwks = key_manager.get_jwks()
        
        # Set cache headers (5 minutes)
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["Content-Type"] = "application/json"
        
        logger.debug(f"Serving JWKS with {len(jwks['keys'])} keys")
        
        return jwks
        
    except Exception as e:
        logger.error(f"Failed to generate JWKS: {e}")
        raise


@router.get("/.well-known/jwks.json")
async def get_jwks_well_known(response: Response) -> Dict:
    """
    Well-known JWKS endpoint (alternative standard location).
    
    Same as /jwks.json but at the standard .well-known location.
    """
    return await get_jwks(response)


@router.get("/keys")
async def list_keys() -> Dict:
    """
    List all keys with metadata (admin endpoint).
    
    Returns information about all keys including active status.
    This is for administrative purposes only.
    """
    try:
        key_manager = get_key_manager()
        keys = key_manager.list_keys()
        
        return {
            "current_kid": key_manager.get_current_kid(),
            "keys": keys
        }
        
    except Exception as e:
        logger.error(f"Failed to list keys: {e}")
        raise


@router.post("/keys/rotate")
async def rotate_keys() -> Dict:
    """
    Rotate to a new key pair (admin endpoint).
    
    Generates a new key and sets it as the current signing key.
    Old keys remain valid for verification during grace period.
    
    Returns information about the new key.
    """
    try:
        key_manager = get_key_manager()
        new_kid = key_manager.rotate_keys()
        
        logger.info(f"Key rotation completed: new kid={new_kid}")
        
        return {
            "status": "rotated",
            "new_kid": new_kid,
            "current_kid": key_manager.get_current_kid(),
            "message": "Key rotation successful. Old keys remain valid for verification."
        }
        
    except Exception as e:
        logger.error(f"Failed to rotate keys: {e}")
        raise


@router.post("/keys/{kid}/deactivate")
async def deactivate_key(kid: str) -> Dict:
    """
    Deactivate a specific key (admin endpoint).
    
    Deactivated keys will no longer be used for signing but can
    still be used for verification of existing tokens.
    
    Args:
        kid: Key ID to deactivate
    """
    try:
        key_manager = get_key_manager()
        
        # Don't allow deactivating current key
        if kid == key_manager.get_current_kid():
            return {
                "status": "error",
                "message": "Cannot deactivate current signing key. Rotate first."
            }
        
        key_manager.deactivate_key(kid)
        
        logger.info(f"Key deactivated: {kid}")
        
        return {
            "status": "deactivated",
            "kid": kid,
            "message": f"Key {kid} has been deactivated"
        }
        
    except Exception as e:
        logger.error(f"Failed to deactivate key {kid}: {e}")
        raise
