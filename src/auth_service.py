from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Header, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import redis
import sqlite3
import re
import time
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, EmailStr
import logging
import secrets
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# P0.1: Import RSA key manager and JWKS router
from crypto import get_key_manager
from jwks import router as jwks_router
from settings import AuthServiceSettings
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, instrument_fastapi, instrument_httpx
from identity_store import (
    IdentityConflict,
    IdentityNotFound,
    IdentityRevoked,
    IdentityStore,
)

# Configure logging
logging.basicConfig(level=logging.INFO)

SETTINGS = AuthServiceSettings.from_env()

# /token rate limiting config
TOKEN_RATE_LIMIT = SETTINGS.rate_limit.limit
TOKEN_RATE_WINDOW = SETTINGS.rate_limit.window_seconds  # seconds

def _rate_limit_key(ip: str) -> str:
    return f"rl:token:{ip}"

def is_rate_limited(ip: str) -> bool:
    """Increment counter for IP and return True if over limit within window."""
    try:
        key = _rate_limit_key(ip)
        with redis_client.pipeline() as pipe:
            pipe.incr(key, 1)
            pipe.expire(key, TOKEN_RATE_WINDOW)
            res = pipe.execute()
        count = int(res[0]) if res and isinstance(res[0], (int,)) else 0
        return count > TOKEN_RATE_LIMIT
    except redis.ConnectionError:
        # Fail-open on rate limit if Redis unavailable, but log warning
        logger.warning("Redis unavailable for rate limiting; skipping limit")
        return False
logger = logging.getLogger(__name__)

app = FastAPI(
    title="unison-auth",
    description="Authentication and Authorization Service for Unison",
    version="1.0.0"
)

# P0.1: Include JWKS router for public key distribution
app.include_router(jwks_router, tags=["jwks"])
 
# P0.3: Add tracing middleware for x-request-id and traceparent propagation
app.add_middleware(TracingMiddleware, service_name="unison-auth")

# P0.3: Initialize tracing and instrument FastAPI/httpx
initialize_tracing()
instrument_fastapi(app)
instrument_httpx()

# Configuration
# P0.1: Removed SECRET_KEY and HS256 - now using RS256 with RSA keys
ALGORITHM = SETTINGS.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = SETTINGS.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_MINUTES = SETTINGS.refresh_token_expire_minutes  # 24 hours

# P0.1: Initialize RSA key manager
key_manager = get_key_manager()

# Redis for token blacklist and session storage
redis_client = redis.Redis(
    host=SETTINGS.redis.host,
    port=SETTINGS.redis.port,
    password=SETTINGS.redis.password,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

# Password hashing
import bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# Pydantic models
class User(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    roles: List[str]
    active: bool = True
    person_id: Optional[str] = None
    assistant_instance_id: Optional[str] = None
    household_id: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[EmailStr] = None
    roles: List[str] = ["user"]

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int

class TokenData(BaseModel):
    username: Optional[str] = None
    roles: List[str] = []
    exp: Optional[int] = None

class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    redis_connected: bool

class BootstrapStatus(BaseModel):
    enabled: bool
    admin_exists: bool
    bootstrap_required: bool
    user_store_path: str
    identity_database_path: str
    schema_version: int

class BootstrapAdminRequest(BaseModel):
    username: str
    password: str
    email: Optional[EmailStr] = None
    display_name: str
    household_name: str = "My household"
    confirmed: bool = False

class InvitationCreateRequest(BaseModel):
    intended_role: str = "adult-member"
    ttl_minutes: int = 30

class InvitationAcceptRequest(BaseModel):
    invitation_token: str
    username: str
    display_name: str
    password: str
    email: Optional[EmailStr] = None

class WorkloadCreateRequest(BaseModel):
    client_id: str
    secret: str
    audiences: List[str]
    scopes: List[str] = []

class PasskeyRegisterRequest(BaseModel):
    challenge_id: str
    challenge: str
    credential_id: str
    public_key_pem: str
    proof_signature_b64: str
    transports: List[str] = []

class PasskeyAuthenticateRequest(BaseModel):
    challenge_id: str
    challenge: str
    credential_id: str
    signature_b64: str
    sign_count: int

class WorkloadDelegationRequest(BaseModel):
    client_id: str
    audience: str
    scopes: List[str]
    purpose: str
    ttl_seconds: int = 300

IDENTITY_STORE = IdentityStore(SETTINGS.identity_database_path)

def has_admin_user() -> bool:
    return IDENTITY_STORE.has_admin()

def validate_password(password: str) -> bool:
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def validate_username(username: str) -> bool:
    """Validate username format"""
    if not re.match(r"^[a-zA-Z0-9_-]{3,32}$", username):
        return False
    return True

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def get_user(username: str) -> Optional[Dict[str, Any]]:
    return IDENTITY_STORE.identity_for_login(username)

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user(username)
    if not user:
        logger.warning(f"Authentication failed: user {username} not found")
        return None
    if not user.get("active", False):
        logger.warning(f"Authentication failed: user {username} is inactive")
        return None
    if not verify_password(password, user["password_hash"]):
        logger.warning(f"Authentication failed: invalid password for {username}")
        return None
    
    logger.info(f"User {username} authenticated successfully")
    return user

def authenticate_service(service_name: str, secret: str) -> Optional[Dict[str, Any]]:
    service = IDENTITY_STORE.workload_for_client(service_name)
    if not service:
        logger.warning(f"Service authentication failed: service {service_name} not found")
        return None
    if not verify_password(secret, service["secret_hash"]):
        logger.warning(f"Service authentication failed: invalid secret for {service_name}")
        return None
    service["username"] = service_name
    service["roles"] = ["service"]
    logger.info(f"Service {service_name} authenticated successfully")
    return service

def person_authority_claims(identity: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Claims are populated only from transactional server-side membership."""
    return {
        "sub": identity["principal_id"],
        "principal_id": identity["principal_id"],
        "principal_kind": "person",
        "person_id": identity["person_id"],
        "assistant_instance_id": identity["assistant_instance_id"],
        "household_id": identity["household_id"],
        "membership_id": identity["membership_id"],
        "login_handle": identity["login_handle"],
        "display_name": identity["display_name"],
        "roles": identity["roles"],
        "scopes": ["assistant:use", "profile:read", "profile:write"],
        "aud": list(SETTINGS.person_audiences),
        "auth_method": "password",
        "assurance": "medium",
        "session_id": session_id,
        "key_handle": identity["key_handle"],
        "credential_namespace": identity["credential_namespace"],
        "data_namespace": identity["data_namespace"],
        "cache_namespace": identity["cache_namespace"],
        "index_namespace": identity["index_namespace"],
    }

def workload_authority_claims(workload: Dict[str, Any], audience: str) -> Dict[str, Any]:
    if audience not in workload["audiences"]:
        raise HTTPException(status_code=403, detail="Requested workload audience is not authorized")
    return {
        "sub": workload["principal_id"],
        "principal_id": workload["principal_id"],
        "principal_kind": "workload",
        "roles": ["service"],
        "scopes": workload["scopes"],
        "aud": [audience],
        "auth_method": "client-secret",
        "assurance": "high",
    }

def _verify_public_key_signature(public_key_pem: str, signature_b64: str, message: bytes) -> None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Only Ed25519 passkey proofs are accepted by this local ceremony")
        signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        public_key.verify(signature, message)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise HTTPException(status_code=401, detail="Passkey proof is invalid") from exc

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = now_utc() + expires_delta
    else:
        expire = now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": "access",
        "iat": now_utc(),
        "jti": f"access_{secrets.token_hex(16)}"
    })
    
    # P0.1: Use RSA key manager to sign with RS256
    encoded_jwt = key_manager.sign_token(to_encode)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = now_utc() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "iat": now_utc(),
        "jti": f"refresh_{secrets.token_hex(16)}"
    })
    
    # P0.1: Use RSA key manager to sign with RS256
    encoded_jwt = key_manager.sign_token(to_encode)
    return encoded_jwt

def is_token_blacklisted(jti: str) -> bool:
    try:
        return redis_client.exists(f"blacklist:{jti}")
    except redis.ConnectionError:
        logger.error("Redis connection error when checking blacklist")
        return True  # Revocation status is unknown: fail closed.

def blacklist_token(jti: str, exp: int):
    """Add token to blacklist with TTL"""
    try:
        ttl = exp - int(time.time())
        if ttl > 0:
            redis_client.setex(f"blacklist:{jti}", ttl, "1")
            logger.info(f"Token {jti} blacklisted")
    except redis.ConnectionError:
        logger.error("Redis connection error when blacklisting token")

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        # P0.1: Use RSA key manager to verify with RS256
        payload = key_manager.verify_token(token)
        return payload
    except JWTError as e:
        logger.warning(f"Token decode error: {e}")
        return None

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not credentials:
        raise credentials_exception
    
    payload = decode_token(credentials.credentials)
    if payload is None:
        raise credentials_exception
    
    username: str = payload.get("login_handle")
    jti: str = payload.get("jti")
    token_type: str = payload.get("type")
    
    if username is None or token_type != "access":
        raise credentials_exception
    
    if is_token_blacklisted(jti):
        raise credentials_exception

    session_id = payload.get("session_id")
    person_id = payload.get("person_id")
    if not session_id or not IDENTITY_STORE.session_is_active(session_id, person_id):
        raise credentials_exception
    
    user = get_user(username=username)
    if user is None:
        raise credentials_exception
    
    return user

def require_roles(required_roles: List[str]):
    """Dependency to require specific roles"""
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_roles = current_user.get("roles", [])
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        return current_user
    return role_checker

# API Endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form(default="password"),
    audience: Optional[str] = Form(default=None),
):
    """OAuth2 compatible token endpoint"""
    # Basic per-IP rate limiting
    client_ip = request.client.host if request and request.client else "unknown"
    if is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": str(TOKEN_RATE_WINDOW)}
        )
    
    if grant_type not in ["password", "client_credentials"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type"
        )
    
    if grant_type == "password":
        # User authentication
        user = authenticate_user(username, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        session_id = IDENTITY_STORE.create_session(
            user,
            auth_method="password",
            assurance="medium",
            lifetime_minutes=REFRESH_TOKEN_EXPIRE_MINUTES,
        )
        claims = person_authority_claims(user, session_id)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data=claims,
            expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(
            data=claims
        )
        
    else:  # client_credentials
        # Service authentication
        service = authenticate_service(username, password)
        if not service:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not audience:
            raise HTTPException(status_code=400, detail="Workload audience is required")
        claims = workload_authority_claims(service, audience)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data=claims,
            expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(
            data=claims
        )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_token: str):
    """Refresh access token using refresh token"""
    
    payload = decode_token(refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    username: str = payload.get("login_handle")
    token_type: str = payload.get("type")
    jti: str = payload.get("jti")
    
    if username is None or token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    if is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked"
        )
    
    if payload.get("principal_kind") != "person":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Workload tokens must be renewed with client credentials",
        )
    if not IDENTITY_STORE.session_is_active(payload.get("session_id", ""), payload.get("person_id")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or expired",
        )

    # Re-read membership and resource handles so refresh cannot preserve stale authority.
    user = get_user(username=username)
    if not user or not user.get("active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    claims = person_authority_claims(user, payload["session_id"])
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data=claims, expires_delta=access_token_expires)
    refresh_token_new = create_refresh_token(data=claims)
    
    # Blacklist old refresh token
    blacklist_token(jti, payload.get("exp", int(time.time()) + 3600))
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token_new,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/logout")
async def logout(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Logout and blacklist current token"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No credentials provided"
        )
    
    payload = decode_token(credentials.credentials)
    if payload:
        jti: str = payload.get("jti")
        exp: int = payload.get("exp", int(time.time()) + 3600)
        blacklist_token(jti, exp)
        session_id = payload.get("session_id")
        if session_id:
            IDENTITY_STORE.revoke_session(session_id, "logout")
    
    return {"message": "Successfully logged out"}

@app.post("/verify")
async def verify_token_endpoint(request: dict):
    """Verify token validity (for internal service use)"""
    token = request.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is required"
        )
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    jti: str = payload.get("jti")
    token_type: str = payload.get("type")
    
    if is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )
    
    if payload.get("session_id"):
        if not IDENTITY_STORE.session_is_active(payload.get("session_id", ""), payload.get("person_id")):
            raise HTTPException(status_code=401, detail="Session has been revoked or expired")
    return {
        "valid": True,
        "username": payload.get("login_handle") or payload.get("sub"),
        "login_handle": payload.get("login_handle"),
        "roles": payload.get("roles", []),
        "type": token_type,
        "exp": payload.get("exp"),
        "claims": payload,
    }

@app.get("/me", response_model=User)
async def read_users_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {
        "username": current_user["login_handle"],
        "email": current_user.get("email"),
        "roles": current_user["roles"],
        "active": current_user.get("active", True),
        "person_id": current_user.get("person_id"),
        "assistant_instance_id": current_user.get("assistant_instance_id"),
        "household_id": current_user.get("household_id"),
    }

@app.get("/admin/users", response_model=List[User])
async def list_users(current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    """List all users (admin only)"""
    users = []
    for user_data in IDENTITY_STORE.list_identities():
        users.append({
            "username": user_data["login_handle"],
            "email": user_data.get("email"),
            "roles": user_data["roles"],
            "active": user_data.get("active", True),
            "person_id": user_data.get("person_id"),
            "assistant_instance_id": user_data.get("assistant_instance_id"),
            "household_id": user_data.get("household_id"),
        })
    return users

@app.post("/admin/users", response_model=User)
async def create_user(
    user: UserCreate,
    current_user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Direct user creation is replaced by household invitation/pairing."""
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Use /households/invitations and /enrollment/accept-invitation",
    )

@app.get("/bootstrap/status", response_model=BootstrapStatus)
async def bootstrap_status():
    """Report whether first-run admin bootstrap is still required."""
    admin_exists = has_admin_user()
    bootstrap_enabled = bool(SETTINGS.bootstrap_token)
    return {
        "enabled": bootstrap_enabled,
        "admin_exists": admin_exists,
        "bootstrap_required": bootstrap_enabled and not admin_exists,
        "user_store_path": SETTINGS.user_store_path,
        "identity_database_path": SETTINGS.identity_database_path,
        "schema_version": IDENTITY_STORE.schema_version(),
    }

@app.post("/bootstrap/admin", response_model=User, status_code=status.HTTP_201_CREATED)
async def bootstrap_admin(
    payload: BootstrapAdminRequest,
    x_unison_bootstrap_token: Optional[str] = Header(default=None, alias="X-Unison-Bootstrap-Token"),
):
    """Create the first admin user through an explicit one-time bootstrap flow."""
    if has_admin_user():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bootstrap is closed because an admin user already exists",
        )

    if not SETTINGS.bootstrap_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bootstrap token is not configured",
        )

    if x_unison_bootstrap_token != SETTINGS.bootstrap_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bootstrap token",
        )

    if not validate_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username format"
        )

    if not validate_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password does not meet security requirements"
        )

    if get_user(payload.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    try:
        identity = IDENTITY_STORE.bootstrap_first_person(
            confirmed=payload.confirmed,
            login_handle=payload.username,
            display_name=payload.display_name,
            household_name=payload.household_name,
            password_hash=get_password_hash(payload.password),
            email=str(payload.email) if payload.email else None,
        )
    except IdentityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    logger.info("First person enrollment completed for login handle %s", payload.username)

    return {
        "username": payload.username,
        "email": payload.email,
        "roles": ["admin"],
        "active": True,
        "person_id": identity["person_id"],
        "assistant_instance_id": identity["assistant_instance_id"],
        "household_id": identity["household_id"],
    }

@app.post("/households/invitations", status_code=status.HTTP_201_CREATED)
async def create_household_invitation(
    payload: InvitationCreateRequest,
    current_user: Dict[str, Any] = Depends(require_roles(["household-admin", "admin"])),
):
    try:
        token, invitation = IDENTITY_STORE.create_invitation(
            invited_by_person_id=current_user["person_id"],
            household_id=current_user["household_id"],
            intended_role=payload.intended_role,
            ttl_minutes=payload.ttl_minutes,
        )
    except IdentityNotFound as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    # The token is shown once and is never stored in recoverable form.
    return {**invitation, "invitation_token": token, "status": "pending"}

@app.post("/enrollment/accept-invitation", response_model=User, status_code=status.HTTP_201_CREATED)
async def accept_household_invitation(payload: InvitationAcceptRequest):
    if not validate_username(payload.username):
        raise HTTPException(status_code=400, detail="Invalid username format")
    if not validate_password(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet security requirements")
    try:
        identity = IDENTITY_STORE.accept_invitation(
            invitation_token=payload.invitation_token,
            login_handle=payload.username,
            display_name=payload.display_name,
            password_hash=get_password_hash(payload.password),
            email=str(payload.email) if payload.email else None,
        )
    except (IdentityNotFound, IdentityRevoked) as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except (IdentityConflict, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=409, detail="Enrollment conflicts with an existing identity") from exc
    return {
        "username": payload.username,
        "email": payload.email,
        "roles": identity["roles"],
        "active": True,
        "person_id": identity["person_id"],
        "assistant_instance_id": identity["assistant_instance_id"],
        "household_id": identity["household_id"],
    }

@app.get("/households/members")
async def list_household_members(current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        return {
            "household_id": current_user["household_id"],
            "members": IDENTITY_STORE.list_household_members(
                requesting_person_id=current_user["person_id"],
                household_id=current_user["household_id"],
            ),
            "private_resources_included": False,
        }
    except IdentityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@app.delete("/households/members/{person_id}")
async def remove_household_member(
    person_id: str,
    current_user: Dict[str, Any] = Depends(require_roles(["household-admin", "admin"])),
):
    try:
        return IDENTITY_STORE.remove_household_member(
            removed_by_person_id=current_user["person_id"],
            household_id=current_user["household_id"],
            person_id=person_id,
        )
    except IdentityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IdentityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@app.post("/admin/workloads", status_code=status.HTTP_201_CREATED)
async def create_workload(
    payload: WorkloadCreateRequest,
    current_user: Dict[str, Any] = Depends(require_roles(["admin"])),
):
    if len(payload.secret) < 24:
        raise HTTPException(status_code=400, detail="Workload secret must contain at least 24 characters")
    try:
        return IDENTITY_STORE.register_workload(
            client_id=payload.client_id,
            secret_hash=get_password_hash(payload.secret),
            audiences=payload.audiences,
            scopes=payload.scopes,
        )
    except (IdentityConflict, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@app.post("/delegations/workload-token")
async def delegate_workload_token(
    payload: WorkloadDelegationRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if not payload.purpose.strip():
        raise HTTPException(status_code=400, detail="Delegation purpose is required")
    if payload.ttl_seconds < 30 or payload.ttl_seconds > 600:
        raise HTTPException(status_code=400, detail="Delegation lifetime must be between 30 and 600 seconds")
    workload = IDENTITY_STORE.workload_for_client(payload.client_id)
    if not workload or payload.audience not in workload["audiences"]:
        raise HTTPException(status_code=403, detail="Workload or audience is not authorized")
    allowed_scopes = set(workload["scopes"])
    requested_scopes = set(payload.scopes)
    if not requested_scopes or not requested_scopes.issubset(allowed_scopes):
        raise HTTPException(status_code=403, detail="Delegation scopes exceed workload authority")
    source_claims = decode_token(credentials.credentials) if credentials else None
    if not source_claims:
        raise HTTPException(status_code=401, detail="Authenticated session is required")
    identity = IDENTITY_STORE.identity_for_person(current_user["person_id"])
    delegation_id = f"dlg_{secrets.token_hex(16)}"
    claims = {
        **person_authority_claims(identity, source_claims["session_id"]),
        "sub": workload["principal_id"],
        "principal_id": workload["principal_id"],
        "principal_kind": "workload",
        "roles": ["service", "delegated"],
        "scopes": sorted(requested_scopes),
        "aud": [payload.audience],
        "auth_method": "delegated-workload",
        "assurance": source_claims.get("assurance", "medium"),
        "delegation_id": delegation_id,
        "delegated_by": current_user["principal_id"],
        "purpose": payload.purpose,
    }
    return {
        "access_token": create_access_token(claims, timedelta(seconds=payload.ttl_seconds)),
        "token_type": "bearer",
        "expires_in": payload.ttl_seconds,
        "delegation_id": delegation_id,
    }

@app.post("/passkeys/register/options")
async def passkey_register_options(current_user: Dict[str, Any] = Depends(get_current_user)):
    challenge_id, challenge = IDENTITY_STORE.issue_challenge(
        person_id=current_user["person_id"],
        purpose="passkey-register",
    )
    return {
        "challenge_id": challenge_id,
        "challenge": challenge,
        "person_id": current_user["person_id"],
        "status": "confirmation-required",
        "expires_in": 300,
    }

@app.post("/passkeys/register/complete", status_code=status.HTTP_201_CREATED)
async def passkey_register_complete(
    payload: PasskeyRegisterRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    person_id = IDENTITY_STORE.consume_challenge(
        payload.challenge_id,
        payload.challenge,
        "passkey-register",
    )
    if person_id != current_user["person_id"]:
        raise HTTPException(status_code=403, detail="Passkey challenge belongs to another principal")
    _verify_public_key_signature(
        payload.public_key_pem,
        payload.proof_signature_b64,
        f"unison-passkey-register:{payload.challenge}".encode("utf-8"),
    )
    try:
        IDENTITY_STORE.register_passkey(
            person_id=person_id,
            credential_id=payload.credential_id,
            public_key_pem=payload.public_key_pem,
            transports=payload.transports,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Passkey credential already exists") from exc
    return {"ok": True, "credential_id": payload.credential_id, "status": "active"}

@app.post("/passkeys/authenticate/options")
async def passkey_authenticate_options(username: str = Body(..., embed=True)):
    identity = get_user(username)
    # Use the same generic response delay/shape at the API boundary; unknown
    # handles receive an unbound challenge that can never complete.
    challenge_id, challenge = IDENTITY_STORE.issue_challenge(
        person_id=identity["person_id"] if identity and identity.get("active") else None,
        purpose="passkey-authenticate",
    )
    return {"challenge_id": challenge_id, "challenge": challenge, "expires_in": 300}

@app.post("/passkeys/authenticate/complete", response_model=Token)
async def passkey_authenticate_complete(payload: PasskeyAuthenticateRequest):
    person_id = IDENTITY_STORE.consume_challenge(
        payload.challenge_id,
        payload.challenge,
        "passkey-authenticate",
    )
    credential = IDENTITY_STORE.passkey(payload.credential_id)
    if not person_id or not credential or credential["person_id"] != person_id:
        raise HTTPException(status_code=401, detail="Passkey authentication failed")
    message = f"unison-passkey-authenticate:{payload.challenge}:{payload.sign_count}".encode("utf-8")
    _verify_public_key_signature(credential["public_key_pem"], payload.signature_b64, message)
    IDENTITY_STORE.advance_passkey_counter(payload.credential_id, payload.sign_count)
    identity = IDENTITY_STORE.identity_for_person(person_id)
    if not identity or not identity.get("active"):
        raise HTTPException(status_code=401, detail="Passkey authentication failed")
    session_id = IDENTITY_STORE.create_session(
        identity,
        auth_method="passkey",
        assurance="high",
        lifetime_minutes=REFRESH_TOKEN_EXPIRE_MINUTES,
    )
    claims = person_authority_claims(identity, session_id)
    claims["auth_method"] = "passkey"
    claims["assurance"] = "high"
    return {
        "access_token": create_access_token(claims, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
        "refresh_token": create_refresh_token(claims),
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

@app.post("/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # A person may revoke their own session. Admin authority does not grant
    # access to another adult's private session identifiers.
    if not IDENTITY_STORE.session_is_active(session_id, current_user["person_id"]):
        raise HTTPException(status_code=404, detail="Session not found")
    IDENTITY_STORE.revoke_session(session_id, "person-request")
    return {"ok": True, "session_id": session_id, "status": "revoked"}

@app.post("/persons/me/lock")
async def lock_current_person(current_user: Dict[str, Any] = Depends(get_current_user)):
    IDENTITY_STORE.lock_person(current_user["person_id"], "person-lock")
    return {"ok": True, "status": "locked"}

@app.get("/healthz", response_model=HealthResponse)
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Liveness check - is the service alive?"""
    return {
        "status": "ok",
        "service": "unison-auth",
        "timestamp": isoformat_utc(),
        "redis_connected": True,
    }

@app.get("/readyz")
@app.get("/ready")
async def readiness_check():
    """Readiness check - is the service ready to serve traffic?"""
    redis_connected = False
    try:
        redis_client.ping()
        redis_connected = True
    except redis.ConnectionError:
        pass
    
    if not redis_connected:
        raise HTTPException(
            status_code=503,
            detail="Service not ready - Redis unavailable"
        )
    
    return {
        "status": "ready",
        "service": "unison-auth",
        "timestamp": isoformat_utc(),
        "dependencies": {
            "redis": "connected"
        }
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "unison-auth",
        "version": "1.0.0",
        "status": "running",
        "bootstrap_required": bool(SETTINGS.bootstrap_token) and not has_admin_user(),
    }

if __name__ == "__main__":
    import uvicorn
    
    # Test Redis connection on startup
    try:
        redis_client.ping()
        logger.info("Redis connection established")
    except redis.ConnectionError:
        logger.error("Could not connect to Redis - authentication may not work properly")
    
    uvicorn.run(
        "auth_service:app",
        host="0.0.0.0",
        port=8088,
        reload=True,
        log_level="info"
    )
from unison_common.datetime_utils import now_utc, isoformat_utc
