# unison-auth

Authentication, token issuance, JWKS publishing, and basic user-management service for UnisonOS.

## Status
Core service (active). The FastAPI app is implemented in `src/auth_service.py`, with JWKS routes in `src/jwks.py`.

## What is implemented
- Token issuance via `POST /token`.
- Token refresh and logout endpoints.
- Token verification and current-user introspection.
- One-time admin bootstrap status and admin creation endpoints.
- Admin user listing and creation endpoints.
- JWKS publishing and key-rotation endpoints.
- Health, readiness, and root metadata endpoints.

## API surface
- `POST /token`
- `POST /refresh`
- `POST /logout`
- `POST /verify`
- `GET /me`
- `GET /bootstrap/status`
- `POST /bootstrap/admin`
- `GET /admin/users`
- `POST /admin/users`
- `GET /jwks.json`
- `GET /.well-known/jwks.json`
- `GET /keys`
- `POST /keys/rotate`
- `POST /keys/{kid}/deactivate`
- `GET /health`, `GET /healthz`
- `GET /ready`, `GET /readyz`
- `GET /`

## Run locally
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
cp .env.example .env
python src/auth_service.py
```

## First Admin Bootstrap

`unison-auth` now supports an explicit one-time admin bootstrap flow instead of relying on shared default credentials.

Required environment:

- `UNISON_AUTH_BOOTSTRAP_TOKEN`
- optional `UNISON_AUTH_USER_STORE_PATH` (defaults to `/keys/users.json`)

Status check:

```bash
curl http://localhost:8083/bootstrap/status
```

Create the first admin:

```bash
curl -X POST http://localhost:8083/bootstrap/admin \
  -H "Content-Type: application/json" \
  -H "X-Unison-Bootstrap-Token: $UNISON_AUTH_BOOTSTRAP_TOKEN" \
  -d '{
    "username": "owner",
    "password": "ReplaceThisWithAStrongPassword!42",
    "email": "owner@example.com"
  }'
```

Behavior:

- bootstrap only succeeds when no active admin already exists
- created users are persisted to the local user store
- later admin-created users are also persisted
- `UNISON_AUTH_DEV_MODE=true` remains a development-only escape hatch and should not be enabled in production
- when dev mode is enabled, seeded users are created only if explicit passwords are supplied via:
  `UNISON_AUTH_DEV_ADMIN_PASSWORD`, `UNISON_AUTH_DEV_OPERATOR_PASSWORD`,
  `UNISON_AUTH_DEV_DEVELOPER_PASSWORD`, and/or `UNISON_AUTH_DEV_USER_PASSWORD`

## Tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```

## Docs
- Public docs: https://project-unisonos.github.io
- Repo docs: `SECURITY.md`
