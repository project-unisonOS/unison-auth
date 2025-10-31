# unison-auth

Authentication and authorization service for the Unison platform, providing secure identity management, token-based authentication, and role-based access control.

## Purpose

The auth service:
- Provides JWT-based authentication with access and refresh tokens
- Implements role-based access control (RBAC) for granular permissions
- Enables secure service-to-service authentication
- Manages token blacklisting and revocation for security
- Supports person management with administrative functions
- Offers OAuth2-compatible token endpoints for integration
- Ensures privacy-first authentication with consent management

## Current Status

### ✅ Implemented
- FastAPI-based HTTP service with comprehensive authentication endpoints
- JWT token system with configurable lifetimes and secure signing
- Role-based access control with hierarchical permissions
- Service-to-service authentication with client credentials flow
- Token blacklisting and secure revocation mechanisms
- Person management with admin functions and user creation
- OAuth2-compatible endpoints for broad integration support
- Redis-based token storage for scalability and performance
- Comprehensive security features including rate limiting and CORS

### 🚧 In Progress
- Multi-factor authentication (MFA) support
- Biometric authentication integration
- Advanced consent management and privacy controls
- Single sign-on (SSO) capabilities
- Advanced audit logging and compliance features

### 📋 Planned
- Federated identity with external providers
- Advanced threat detection and anomaly detection
- Zero-trust architecture implementation
- Hardware security module (HSM) integration

## Quick Start

### Local Development
```bash
# Clone and setup
git clone https://github.com/project-unisonOS/unison-auth
cd unison-auth

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export UNISON_JWT_SECRET="your-256-bit-secret-key-here"
export REDIS_HOST="localhost"
export REDIS_PORT="6379"

# Run the service
python src/auth_service.py
```

### Docker Deployment
```bash
# Using the development stack
cd ../unison-devstack
docker-compose up -d auth

# Health check
curl http://localhost:8088/health
```

### Security-Hardened Deployment
```bash
# Using the security configuration
cd ../unison-devstack
docker-compose -f docker-compose.security.yml up -d

# Access through internal network
curl http://auth:8088/health
```

## API Reference

### Authentication Endpoints
- `POST /token` - OAuth2-compatible token endpoint
- `POST /refresh` - Refresh access token using refresh token
- `POST /logout` - Logout and blacklist current token
- `POST /verify` - Verify token validity (internal service use)

### Person Management
- `GET /me` - Get current person information
- `GET /admin/people` - List all people (admin only)
- `POST /admin/people` - Create new person (admin only)
- `PUT /admin/people/{person_id}` - Update person (admin only)
- `DELETE /admin/people/{person_id}` - Delete person (admin only)

### System Endpoints
- `GET /health` - Service health check
- `GET /ready` - Dependency readiness check
- `GET /metrics` - Authentication metrics

### Authentication Examples
```bash
# Get access token for person
curl -X POST http://localhost:8088/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin123"

# Service-to-service authentication
curl -X POST http://localhost:8088/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&username=service-orchestrator&password=orchestrator-secret"

# Verify token
curl -X POST http://localhost:8088/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."}'
```

[Full API Documentation](../../unison-docs/developer/api-reference/auth.md)

## Configuration

### Environment Variables
```bash
# Service Configuration
AUTH_PORT=8088                        # Service port
AUTH_HOST=0.0.0.0                     # Service host

# Security Configuration
UNISON_JWT_SECRET=your-256-bit-key   # JWT signing secret (256-bit minimum)
UNISON_ACCESS_TOKEN_EXPIRE_MINUTES=30  # Access token lifetime
UNISON_REFRESH_TOKEN_EXPIRE_MINUTES=1440 # Refresh token lifetime

# Redis Configuration
REDIS_HOST=localhost                  # Redis server hostname
REDIS_PORT=6379                       # Redis server port
REDIS_PASSWORD=your-redis-password    # Redis server password
REDIS_DB=0                            # Redis database number

# Service Authentication
UNISON_ORCHESTRATOR_SERVICE_SECRET=orchestrator-secret
UNISON_INFERENCE_SERVICE_SECRET=inference-secret
UNISON_POLICY_SERVICE_SECRET=policy-secret
UNISON_CONTEXT_SERVICE_SECRET=context-secret
UNISON_STORAGE_SERVICE_SECRET=storage-secret

# Security Features
AUTH_ENABLE_RATE_LIMITING=true        # Enable rate limiting
AUTH_MAX_LOGIN_ATTEMPTS=5             # Max failed login attempts
AUTH_LOCKOUT_DURATION=900             # Account lockout duration (seconds)
AUTH_ENABLE_CORS=true                 # Enable CORS
AUTH_CORS_ORIGINS=["http://localhost:3000"] # Allowed origins
```

## Authentication Model

### Person Structure
```json
{
  "person_id": "person-123",
  "username": "admin",
  "email": "admin@unisonos.org",
  "roles": ["admin"],
  "active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "last_login": "2024-01-01T14:30:00Z",
  "preferences": {
    "theme": "dark",
    "language": "en",
    "notifications": true
  },
  "security": {
    "mfa_enabled": false,
    "password_changed_at": "2024-01-01T12:00:00Z",
    "failed_login_attempts": 0
  }
}
```

### Token Structure
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "scope": "read write admin",
  "person_id": "person-123"
}
```

## Role-Based Access Control

### Role Hierarchy
```
admin (highest privilege)
├── operator (service management)
├── developer (development access)
└── person (basic access)
```

### Role Permissions
- **admin**: Full system access, person management, system configuration
- **operator**: Service management, monitoring, operational tasks
- **developer**: Development tools, testing, debugging access
- **person**: Basic intent execution, personal data access

### Permission Scopes
- `read` - Access to read operations
- `write` - Access to write operations
- `admin` - Administrative operations
- `service` - Service-to-service communication

## Development

### Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Initialize test data
python scripts/init_test_data.py

# Run tests
pytest tests/

# Run with debug logging
LOG_LEVEL=DEBUG python src/auth_service.py
```

### Testing
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Security tests
pytest tests/security/

# Performance tests
pytest tests/performance/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive security tests
4. Ensure all authentication and security tests pass
5. Submit a pull request with detailed security review

[Development Guide](../../unison-docs/developer/contributing.md)

## Security and Privacy

### Authentication Security
- **Strong Cryptography**: 256-bit secrets for JWT signing
- **Token Management**: Short-lived access tokens, long-lived refresh tokens
- **Secure Storage**: Redis-based token storage with encryption
- **Rate Limiting**: Protection against brute force attacks
- **Account Lockout**: Automatic lockout after failed attempts

### Privacy Protection
- **Data Minimization**: Only collect necessary authentication data
- **Consent Management**: Explicit consent for data processing
- **Right to Deletion**: Complete account and data deletion
- **Audit Logging**: Comprehensive logging for security and compliance
- **Encryption**: All sensitive data encrypted at rest and in transit

### Compliance
- **GDPR Compliance**: Right to access, rectify, and delete data
- **Security Standards**: Industry best practices for authentication
- **Audit Requirements**: Complete audit trail for all authentication events
- **Data Protection**: Privacy by design in all authentication flows

[Security Documentation](../../unison-docs/operations/security.md)

## Architecture

### Auth Service Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Layer     │───▶│  Auth Engine     │───▶│  Token Manager  │
│ (FastAPI)       │    │ (Authentication) │    │ (JWT & Redis)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  RBAC Manager    │
                       │ (Roles &         │
                       │  Permissions)    │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Security Layer  │
                       │ (Rate Limiting   │
                       │  & Protection)   │
                       └──────────────────┘
```

### Authentication Flow
1. **Request**: Client provides credentials
2. **Validation**: Verify credentials against database
3. **Token Generation**: Create signed JWT tokens
4. **Role Assignment**: Assign roles and permissions
5. **Storage**: Store tokens in Redis for validation
6. **Response**: Return tokens to client

[Architecture Documentation](../../unison-docs/developer/architecture.md)

## Monitoring

### Health Checks
- `/health` - Basic service health
- `/ready` - Redis connectivity and readiness
- `/metrics` - Authentication operation metrics

### Metrics
Key metrics available:
- Authentication attempts per second
- Success/failure rates by endpoint
- Active token count and distribution
- Role-based access patterns
- Security events and lockouts
- Token refresh and revocation rates

### Logging
Structured JSON logging with correlation IDs:
- Authentication success and failure events
- Token operations (creation, refresh, revocation)
- Security warnings and violations
- Role changes and permission updates
- Performance metrics and bottlenecks

[Monitoring Guide](../../unison-docs/operations/monitoring.md)

## Default Configuration

### Default People
For development and testing:
| Username | Password | Roles | Purpose |
|----------|----------|-------|---------|
| admin | admin123 | admin | System administration |
| operator | operator123 | operator | Service operations |
| developer | dev123 | developer | Development and testing |
| person | person123 | person | Basic usage |

⚠️ **Change all default passwords in production!**

### Service Accounts
Default service credentials:
| Service | Username | Secret | Purpose |
|---------|----------|--------|---------|
| orchestrator | service-orchestrator | orchestrator-secret | Core orchestration |
| inference | service-inference | inference-secret | AI model access |
| policy | service-policy | policy-secret | Policy evaluation |
| context | service-context | context-secret | Context management |
| storage | service-storage | storage-secret | Data storage |

## Related Services

### Dependencies
- **Redis** - Token storage and caching
- **PostgreSQL** - Person and role data storage

### Consumers
- **unison-orchestrator** - Primary authentication consumer
- **unison-context** - Person context and preferences
- **unison-policy** - Policy-based access control
- **unison-storage** - Secure data access
- **All services** - Service-to-service authentication

## Troubleshooting

### Common Issues

**Redis Connection Failed**
```bash
# Check Redis connectivity
redis-cli -h localhost -p 6379 ping

# Verify Redis configuration
grep REDIS_ .env

# Check Redis logs
docker-compose logs redis
```

**Token Validation Errors**
```bash
# Check JWT secret
grep UNISON_JWT_SECRET .env

# Verify token format
python scripts/validate_token.py <token>

# Check blacklist status
curl -X GET http://localhost:8088/admin/blacklist \
  -H "Authorization: Bearer <admin-token>"
```

**Authentication Failures**
```bash
# Check person credentials
curl -X POST http://localhost:8088/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin123"

# Verify role assignments
curl -X GET http://localhost:8088/me \
  -H "Authorization: Bearer <token>"

# Check account lockout status
python scripts/check_lockout.py --username admin
```

### Debug Mode
```bash
# Enable verbose logging
LOG_LEVEL=DEBUG AUTH_DEBUG_TOKENS=true python src/auth_service.py

# Monitor authentication events
docker-compose logs -f auth | jq '.'

# Test authentication flow
python scripts/test_auth.py --all
```

[Troubleshooting Guide](../../unison-docs/people/troubleshooting.md)

## Version Compatibility

| Auth Version | Unison Common | Minimum Redis | Minimum Docker |
|--------------|---------------|---------------|----------------|
| 1.0.0        | 1.0.0         | 6.0+          | 20.10+         |
| 0.9.x        | 0.9.x         | 5.0+          | 20.04+         |

[Compatibility Matrix](../../unison-spec/specs/version-compatibility.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [Project Unison Docs](https://github.com/project-unisonOS/unison-docs)
- **Issues**: [GitHub Issues](https://github.com/project-unisonOS/unison-auth/issues)
- **Discussions**: [GitHub Discussions](https://github.com/project-unisonOS/unison-auth/discussions)
- **Security**: Report security issues to security@unisonos.org
