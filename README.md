# unison-auth

Authentication, token issuance, JWKS publishing, and basic user-management service for UnisonOS.

## Status
Core service (active). The FastAPI app is implemented in `src/auth_service.py`, with JWKS routes in `src/jwks.py`.

## What is implemented
- Token issuance via `POST /token`.
- Token refresh and logout endpoints.
- Token verification and current-user introspection.
- Admin user listing and creation endpoints.
- JWKS publishing and key-rotation endpoints.
- Health, readiness, and root metadata endpoints.

## API surface
- `POST /token`
- `POST /refresh`
- `POST /logout`
- `POST /verify`
- `GET /me`
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

## Tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```

## Docs
- Public docs: https://project-unisonos.github.io
- Repo docs: `SECURITY.md`
