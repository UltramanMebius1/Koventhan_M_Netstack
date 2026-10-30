"""Cryptographic primitives: password hashing and session-token handling.

No third-party crypto and no auth library: scrypt comes from the standard
library (OpenSSL), randomness from `secrets` / `os.urandom`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets

_PREFIX = "scrypt"
_SALT_LEN = 16
_KEY_LEN = 32

# ----------------------------------------------------------------- passwords


def _maxmem(n: int, r: int, p: int) -> int:
    # OpenSSL needs ~128*r*(n+p+2) bytes; allow 2x headroom.
    return 2 * 128 * r * (n + p + 2)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hash_password(password: str, *, n: int, r: int, p: int) -> str:
    """Return a self-describing hash: scrypt$N$r$p$salt_b64$hash_b64.

    A fresh 16-byte random salt is generated per call, i.e. per user/password.
    Parameters are stored in the string so cost can be raised later without
    breaking existing hashes.
    """
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        maxmem=_maxmem(n, r, p), dklen=_KEY_LEN,
    )
    return "$".join([_PREFIX, str(n), str(r), str(p), _b64(salt), _b64(dk)])


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. Any malformed stored value simply returns False."""
    try:
        prefix, n_s, r_s, p_s, salt_s, hash_s = stored.split("$")
        if prefix != _PREFIX:
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        # Sanity bounds so a corrupted/tampered row cannot make us allocate GiBs.
        if n < 2 or n & (n - 1) or not (1 <= r <= 32) or not (1 <= p <= 16) or n * r > 2**22:
            return False
        salt = base64.b64decode(salt_s, validate=True)
        expected = base64.b64decode(hash_s, validate=True)
        if not (16 <= len(expected) <= 64) or len(salt) < 8:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            maxmem=_maxmem(n, r, p), dklen=len(expected),
        )
    except (ValueError, TypeError):  # binascii.Error is a ValueError
        return False
    return hmac.compare_digest(actual, expected)


# ------------------------------------------------------------------ sessions

_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def new_session_token() -> str:
    """256 bits from the OS CSPRNG, URL-safe base64 (43 chars). Opaque: it
    encodes nothing about the user, role or expiry."""
    return secrets.token_urlsafe(32)


def looks_like_token(candidate: str) -> bool:
    return _TOKEN_RE.fullmatch(candidate) is not None


def hash_token(token: str) -> str:
    """Only this digest is stored server-side, so a leaked sessions table does
    not yield usable tokens. A fast hash is correct here (and a slow one would
    be pointless): the input already has 256 bits of entropy, so there is
    nothing to brute-force."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()
