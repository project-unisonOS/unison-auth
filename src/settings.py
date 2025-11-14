"""Typed configuration for the unison-auth service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class RedisSettings:
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None


@dataclass(frozen=True)
class RateLimitSettings:
    limit: int = 10
    window_seconds: int = 60


@dataclass(frozen=True)
class AuthServiceSettings:
    algorithm: str = "RS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 1440
    redis: RedisSettings = field(default_factory=RedisSettings)
    rate_limit: RateLimitSettings = field(default_factory=RateLimitSettings)

    @classmethod
    def from_env(cls) -> "AuthServiceSettings":
        return cls(
            algorithm=os.getenv("UNISON_AUTH_ALGORITHM", "RS256"),
            access_token_expire_minutes=int(os.getenv("UNISON_ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
            refresh_token_expire_minutes=int(os.getenv("UNISON_REFRESH_TOKEN_EXPIRE_MINUTES", "1440")),
            redis=RedisSettings(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                password=os.getenv("REDIS_PASSWORD"),
            ),
            rate_limit=RateLimitSettings(
                limit=int(os.getenv("AUTH_TOKEN_RATE_LIMIT", "10")),
                window_seconds=int(os.getenv("AUTH_TOKEN_RATE_WINDOW_SECONDS", "60")),
            ),
        )


__all__ = ["AuthServiceSettings", "RedisSettings", "RateLimitSettings"]
