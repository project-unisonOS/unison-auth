from __future__ import annotations

from src.settings import AuthServiceSettings


def test_auth_settings_defaults(monkeypatch):
    keys = [
        "UNISON_AUTH_ALGORITHM",
        "UNISON_ACCESS_TOKEN_EXPIRE_MINUTES",
        "UNISON_REFRESH_TOKEN_EXPIRE_MINUTES",
        "AUTH_TOKEN_RATE_LIMIT",
        "AUTH_TOKEN_RATE_WINDOW_SECONDS",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_PASSWORD",
    ]
    for key in keys:
        monkeypatch.delenv(key, raising=False)

    settings = AuthServiceSettings.from_env()

    assert settings.algorithm == "RS256"
    assert settings.access_token_expire_minutes == 30
    assert settings.refresh_token_expire_minutes == 1440
    assert settings.rate_limit.limit == 10
    assert settings.rate_limit.window_seconds == 60
    assert settings.redis.host == "localhost"
    assert settings.redis.port == 6379
    assert settings.redis.password is None


def test_auth_settings_env_overrides(monkeypatch):
    overrides = {
        "UNISON_AUTH_ALGORITHM": "HS512",
        "UNISON_ACCESS_TOKEN_EXPIRE_MINUTES": "45",
        "UNISON_REFRESH_TOKEN_EXPIRE_MINUTES": "60",
        "AUTH_TOKEN_RATE_LIMIT": "25",
        "AUTH_TOKEN_RATE_WINDOW_SECONDS": "120",
        "REDIS_HOST": "redis",
        "REDIS_PORT": "6380",
        "REDIS_PASSWORD": "secret",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)

    settings = AuthServiceSettings.from_env()

    assert settings.algorithm == "HS512"
    assert settings.access_token_expire_minutes == 45
    assert settings.refresh_token_expire_minutes == 60
    assert settings.rate_limit.limit == 25
    assert settings.rate_limit.window_seconds == 120
    assert settings.redis.host == "redis"
    assert settings.redis.port == 6380
    assert settings.redis.password == "secret"
