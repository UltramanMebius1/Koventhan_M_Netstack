"""Authentication: proving who is calling.

No auth library. Sessions are opaque random tokens looked up server-side.
"""
from __future__ import annotations

import logging
from functools import wraps

from flask import current_app, g, request

from . import lockout, security, store
from .authz import User
from .db import get_db
from .errors import ApiError

security_log = logging.getLogger("nestack.security")


def now() -> int:
    """Injectable clock (tests replace app.config['CLOCK'])."""
    return int(current_app.config["CLOCK"]())


# ---------------------------------------------------------------- credentials

def burn_hash(password: str) -> None:
    """Spend the same CPU as a real verification so response time does not
    reveal whether a username exists."""
    security.verify_password(password, current_app.extensions["dummy_hash"])


def check_credentials(username: str, password: str):
    """Throttle, then verify. Returns the user row, or None on bad credentials.
    Raises ApiError(429) when the account is locked."""
    db = get_db()
    cfg = current_app.extensions["cfg"]
    t = now()

    store.purge_stale_attempts(db, t, cfg.max_lockout_seconds)
    retry_after = lockout.reserve_attempt(db, username, cfg, t)
    if retry_after:
        security_log.warning("login blocked (account locked) user=%s retry_after=%s", username, retry_after)
        raise ApiError(429, "too many failed login attempts; try again later",
                       headers={"Retry-After": str(retry_after)})

    user = store.get_user_by_username(db, username)
    if user is None:
        burn_hash(password)
        ok = False
    else:
        ok = security.verify_password(password, user["password_hash"])

    if not ok:
        security_log.info("login failed user=%s", username)
        return None
    lockout.clear(db, username)
    return user


# ------------------------------------------------------------------- sessions

def issue_session(user_id: int) -> tuple[str, int]:
    cfg = current_app.extensions["cfg"]
    db = get_db()
    t = now()
    store.purge_expired_sessions(db, t)
    token = security.new_session_token()
    store.create_session(db, security.hash_token(token), user_id, t, t + cfg.session_ttl_seconds)
    return token, cfg.session_ttl_seconds


def _unauthorized() -> ApiError:
    return ApiError(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})


def _bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    scheme, sep, token = header.partition(" ")
    if not sep or scheme.lower() != "bearer" or not security.looks_like_token(token):
        raise _unauthorized()
    return token


def require_auth(view):
    """Resolve the bearer token to a user on EVERY request. Identity and role
    come from the server-side session/user rows, never from the token itself."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        token_hash = security.hash_token(_bearer_token())
        row = store.get_session_user(get_db(), token_hash, now())
        if row is None:
            raise _unauthorized()
        g.user = User(id=row["id"], username=row["username"], role=row["role"])
        g.token_hash = token_hash
        return view(*args, **kwargs)
    return wrapper
