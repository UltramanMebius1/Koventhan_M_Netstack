"""Environment-based configuration.

The service needs no secrets at all (see README: sessions are opaque random
tokens, so there is no signing key to protect or leak). Everything here is a
tuning knob with a safe default.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Floor for scrypt cost when configuration comes from the environment, so a
# typo in a deployment config cannot silently weaken password hashing.
MIN_SCRYPT_N = 2**14


@dataclass(frozen=True)
class Config:
    database_path: str = "records.db"

    # Sessions
    session_ttl_seconds: int = 3600

    # Per-account login throttling
    max_failed_logins: int = 5
    failure_window_seconds: int = 900
    lockout_seconds: int = 900
    max_lockout_seconds: int = 86400

    # Request limits
    max_body_bytes: int = 131072

    # Password hashing (scrypt). OWASP-equivalent: N=2^15, r=8, p=3 (~32 MiB).
    scrypt_n: int = 2**15
    scrypt_r: int = 8
    scrypt_p: int = 3

    @classmethod
    def from_env(cls) -> "Config":
        d = cls()
        cfg = cls(
            database_path=os.environ.get("DATABASE_PATH", d.database_path),
            session_ttl_seconds=_int("SESSION_TTL_SECONDS", d.session_ttl_seconds, 60),
            max_failed_logins=_int("MAX_FAILED_LOGINS", d.max_failed_logins, 1),
            failure_window_seconds=_int("FAILURE_WINDOW_SECONDS", d.failure_window_seconds, 1),
            lockout_seconds=_int("LOCKOUT_SECONDS", d.lockout_seconds, 1),
            max_lockout_seconds=_int("MAX_LOCKOUT_SECONDS", d.max_lockout_seconds, 1),
            max_body_bytes=_int("MAX_BODY_BYTES", d.max_body_bytes, 1024),
            scrypt_n=_int("SCRYPT_N", d.scrypt_n, MIN_SCRYPT_N),
            scrypt_r=_int("SCRYPT_R", d.scrypt_r, 8),
            scrypt_p=_int("SCRYPT_P", d.scrypt_p, 1),
        )
        if cfg.scrypt_n & (cfg.scrypt_n - 1):
            raise RuntimeError("SCRYPT_N must be a power of two")
        return cfg


def _int(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer") from None
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value
