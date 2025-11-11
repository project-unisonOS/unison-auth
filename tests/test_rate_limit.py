import pytest
from fastapi.testclient import TestClient

import os, sys, types
src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, src_dir)
pkg = types.ModuleType("unison_auth")
pkg.__path__ = [src_dir]
sys.modules.setdefault("unison_auth", pkg)

# Stub out tracing exporter dependencies to avoid optional deps during unit tests
stub = types.ModuleType("opentelemetry.exporter.jaeger.thrift")
class _DummyJaegerExporter:
    def __init__(self, *args, **kwargs):
        pass
    def export(self, *args, **kwargs):
        return None
    def shutdown(self):
        pass
stub.JaegerExporter = _DummyJaegerExporter
sys.modules.setdefault("deprecated", types.ModuleType("deprecated"))
sys.modules.setdefault("opentelemetry.exporter.jaeger", types.ModuleType("opentelemetry.exporter.jaeger"))
sys.modules.setdefault("opentelemetry.exporter.jaeger.thrift", stub)

# Stub unison_common.tracing and middleware to no-ops prior to import
tracing_stub = types.ModuleType("unison_common.tracing")
def _noop(*args, **kwargs):
    return None
tracing_stub.initialize_tracing = _noop
tracing_stub.instrument_fastapi = _noop
tracing_stub.instrument_httpx = _noop
sys.modules.setdefault("unison_common.tracing", tracing_stub)

tm_stub = types.ModuleType("unison_common.tracing_middleware")
class _TM:
    def __init__(self, app, **kwargs):
        self.app = app
    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)
tm_stub.TracingMiddleware = _TM
sys.modules.setdefault("unison_common.tracing_middleware", tm_stub)

os.environ.setdefault("OTEL_TRACES_EXPORTER", "none")
os.environ.setdefault("OTEL_METRICS_EXPORTER", "none")
os.environ.setdefault("OTEL_LOGS_EXPORTER", "none")

from unison_auth.auth_service import app, is_rate_limited


def test_token_rate_limit_returns_429(monkeypatch):
    # Force rate-limited path
    monkeypatch.setattr("unison_auth.auth_service.is_rate_limited", lambda ip: True)
    client = TestClient(app)
    resp = client.post(
        "/token",
        data={
            "username": "any",
            "password": "any",
            "grant_type": "password",
        },
    )
    assert resp.status_code == 429
    assert resp.json()["detail"].lower().startswith("rate limit")
