from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import redis
import os
import re
import time
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, EmailStr
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="unison-auth",
    description="Authentication and Authorization Service for Unison",
    version="1.0.0"
)

# Configuration
SECRET_KEY = os.getenv("UNISON_JWT_SECRET", "change-this-secret-key-in-production-256-bits-minimum")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("UNISON_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("UNISON_REFRESH_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

# Redis for token blacklist and session storage
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD"),
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5
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

# Mock user database (replace with real database in production)
USERS_DB = {
    "admin": {
        "username": "admin",
        "email": "admin@unison.local",
        "hashed_password": "$2b$12$cE3Q0zl9Gf3Ur4IDzI1WLOMZbADNLlNGMuREOSoQk.wKQorvumtAu",  # 'admin123'
        "roles": ["admin"],
        "active": True,
        "created_at": datetime.utcnow().isoformat()
    },
    "operator": {
        "username": "operator",
        "email": "operator@unison.local",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # 'operator123'
        "roles": ["operator"],
        "active": True,
        "created_at": datetime.utcnow().isoformat()
    },
    "developer": {
        "username": "developer",
        "email": "dev@unison.local",
        "hashed_password": "$2b$12$9DhGvMweApXn5gEksNl4nOJG4wB9f7kL8aXqFqk9X2YjVzZ3Rw5e",  # 'dev123'
        "roles": ["developer"],
        "active": True,
        "created_at": datetime.utcnow().isoformat()
    },
    "user": {
        "username": "user",
        "email": "user@unison.local",
        "hashed_password": "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",  # 'user123'
        "roles": ["user"],
        "active": True,
        "created_at": datetime.utcnow().isoformat()
    }
}

# Service accounts for inter-service communication
SERVICE_ACCOUNTS = {
    "orchestrator": {
        "username": "service-orchestrator",
        "secret": os.getenv("UNISON_ORCHESTRATOR_SERVICE_SECRET", "orchestrator-secret"),
        "roles": ["service"]
    },
    "inference": {
        "username": "service-inference",
        "secret": os.getenv("UNISON_INFERENCE_SERVICE_SECRET", "inference-secret"),
        "roles": ["service"]
    },
    "policy": {
        "username": "service-policy",
        "secret": os.getenv("UNISON_POLICY_SERVICE_SECRET", "policy-secret"),
        "roles": ["service"]
    }
}

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
    return USERS_DB.get(username)

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user(username)
    if not user:
        logger.warning(f"Authentication failed: user {username} not found")
        return None
    if not user.get("active", False):
        logger.warning(f"Authentication failed: user {username} is inactive")
        return None
    if not verify_password(password, user["hashed_password"]):
        logger.warning(f"Authentication failed: invalid password for {username}")
        return None
    
    logger.info(f"User {username} authenticated successfully")
    return user

def authenticate_service(service_name: str, secret: str) -> Optional[Dict[str, Any]]:
    service = SERVICE_ACCOUNTS.get(service_name)
    if not service:
        logger.warning(f"Service authentication failed: service {service_name} not found")
        return None
    if service["secret"] != secret:
        logger.warning(f"Service authentication failed: invalid secret for {service_name}")
        return None
    
    logger.info(f"Service {service_name} authenticated successfully")
    return service

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": "access",
        "iat": datetime.utcnow(),
        "jti": f"access_{int(time.time())}_{data.get('sub', 'unknown')}"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "iat": datetime.utcnow(),
        "jti": f"refresh_{int(time.time())}_{data.get('sub', 'unknown')}"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def is_token_blacklisted(jti: str) -> bool:
    try:
        return redis_client.exists(f"blacklist:{jti}")
    except redis.ConnectionError:
        logger.error("Redis connection error when checking blacklist")
        return False  # Fail safe - allow token if Redis is down

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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
    
    username: str = payload.get("sub")
    jti: str = payload.get("jti")
    token_type: str = payload.get("type")
    
    if username is None or token_type != "access":
        raise credentials_exception
    
    if is_token_blacklisted(jti):
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
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form(default="password")
):
    """OAuth2 compatible token endpoint"""
    
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
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"], "roles": user["roles"]}, 
            expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(
            data={"sub": user["username"], "roles": user["roles"]}
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
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": service["username"], "roles": service["roles"]}, 
            expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(
            data={"sub": service["username"], "roles": service["roles"]}
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
    
    username: str = payload.get("sub")
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
    
    # Check if user is still active
    user = get_user(username=username)
    if not user and not username.startswith("service-"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    if user:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"], "roles": user["roles"]}, 
            expires_delta=access_token_expires
        )
        refresh_token_new = create_refresh_token(
            data={"sub": user["username"], "roles": user["roles"]}
        )
    else:
        # Service account
        service = SERVICE_ACCOUNTS.get(username.replace("service-", ""))
        if service:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": service["username"], "roles": service["roles"]}, 
                expires_delta=access_token_expires
            )
            refresh_token_new = create_refresh_token(
                data={"sub": service["username"], "roles": service["roles"]}
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Service not found"
            )
    
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
    
    return {
        "valid": True,
        "username": payload.get("sub"),
        "roles": payload.get("roles", []),
        "type": token_type,
        "exp": payload.get("exp")
    }

@app.get("/me", response_model=User)
async def read_users_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {
        "username": current_user["username"],
        "email": current_user.get("email"),
        "roles": current_user["roles"],
        "active": current_user.get("active", True)
    }

@app.get("/admin/users", response_model=List[User])
async def list_users(current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    """List all users (admin only)"""
    users = []
    for username, user_data in USERS_DB.items():
        users.append({
            "username": user_data["username"],
            "email": user_data.get("email"),
            "roles": user_data["roles"],
            "active": user_data.get("active", True)
        })
    return users

@app.post("/admin/users", response_model=User)
async def create_user(
    user: UserCreate,
    current_user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """Create new user (admin only)"""
    
    if not validate_username(user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username format"
        )
    
    if not validate_password(user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password does not meet security requirements"
        )
    
    if user.username in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    
    # Create user
    hashed_password = get_password_hash(user.password)
    USERS_DB[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "roles": user.roles,
        "active": True,
        "created_at": datetime.utcnow().isoformat()
    }
    
    logger.info(f"User {user.username} created by admin {current_user['username']}")
    
    return {
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "active": True
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    redis_connected = False
    try:
        redis_client.ping()
        redis_connected = True
    except redis.ConnectionError:
        pass
    
    return {
        "status": "ok",
        "service": "unison-auth",
        "timestamp": datetime.utcnow().isoformat(),
        "redis_connected": redis_connected
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "unison-auth",
        "version": "1.0.0",
        "status": "running"
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
