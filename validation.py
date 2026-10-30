"""Input validation. Everything a client sends passes through here before it
touches business logic or the database. Failures are ApiError(400) with a
generic message; input values are never echoed back."""
from __future__ import annotations

import re
from typing import Iterable

from flask import request

from .errors import ApiError

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}", re.ASCII)
RECORD_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)

PASSWORD_MIN, PASSWORD_MAX = 8, 128
TITLE_MAX = 200
BODY_MAX = 10_000
LOGIN_USERNAME_MAX = 64

# Keys that look like an attempt to choose a privilege level. Matched after
# lower-casing and stripping "_", "-", "." so isAdmin / is_admin / Is-Admin all hit.
_PRIVILEGE_KEYS = frozenset({
    "role", "roles", "userrole", "isadmin", "admin", "issuperuser", "superuser",
    "isstaff", "staff", "permissions", "scope", "scopes", "privileges", "accounttype",
})


def _norm_key(key: str) -> str:
    return re.sub(r"[_\-.]", "", key.lower())


def read_json_object(*, required: Iterable[str], optional: Iterable[str] = (),
                     reject_privilege_fields: bool = False) -> dict:
    """Parse the request body as a JSON *object* with an exact set of keys.

    - not JSON / wrong content-type / malformed / not an object  -> 400
    - body over MAX_CONTENT_LENGTH                               -> 400 (see app/__init__.py)
    - privilege-looking key (role, isAdmin, ...)                 -> 403   [reject_privilege_fields]
    - any other unknown key (e.g. owner_id)                      -> 400   (no mass assignment)
    - missing required key                                       -> 400
    """
    required = set(required)
    allowed = required | set(optional)
    try:
        data = request.get_json(silent=True)
    except RecursionError:  # absurdly nested JSON
        data = None
    if not isinstance(data, dict):
        raise ApiError(400, "request body must be a JSON object")

    if reject_privilege_fields and any(_norm_key(k) in _PRIVILEGE_KEYS for k in data):
        raise ApiError(403, "role and privileges cannot be set by clients")

    if set(data) - allowed:
        raise ApiError(400, "unexpected field in request body")
    if required - set(data):
        raise ApiError(400, "missing required field")
    return data


def require_str(value, field: str, *, min_len: int = 1, max_len: int, allow_blank: bool = False) -> str:
    if not isinstance(value, str):  # also rejects bool/int/list/dict/None
        raise ApiError(400, f"{field} must be a string")
    if len(value) < min_len or len(value) > max_len:
        raise ApiError(400, f"{field} must be between {min_len} and {max_len} characters")
    try:
        value.encode("utf-8")  # lone surrogates (JSON "\ud800") would crash hashing/SQLite later
    except UnicodeEncodeError:
        raise ApiError(400, f"{field} contains invalid characters") from None
    if not allow_blank and not value.strip():
        raise ApiError(400, f"{field} must not be blank")
    return value


def normalise_username(raw: str) -> str | None:
    """Canonical form used for storage, lookup AND lockout accounting:
    'Alice' and 'alice' are the same account (so case games cannot dodge a
    lockout). Returns None if the string can never be a valid username."""
    if USERNAME_RE.fullmatch(raw) is None:
        return None
    return raw.lower()


def validate_new_username(value) -> str:
    raw = require_str(value, "username", min_len=3, max_len=32)
    name = normalise_username(raw)
    if name is None:
        raise ApiError(400, "username may only contain letters, digits, '_', '.' and '-'")
    return name


def validate_new_password(value, username: str | None = None) -> str:
    pw = require_str(value, "password", min_len=PASSWORD_MIN, max_len=PASSWORD_MAX, allow_blank=True)
    if not pw.strip():
        raise ApiError(400, "password must not be blank")
    if username and pw.lower() == username.lower():
        raise ApiError(400, "password must not equal the username")
    return pw


def is_valid_record_id(value: str) -> bool:
    return RECORD_ID_RE.fullmatch(value) is not None
