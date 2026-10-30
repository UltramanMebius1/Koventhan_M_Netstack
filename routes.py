"""HTTP layer: parse -> validate -> call auth/authz/store -> serialise.
No SQL and no crypto here."""
from __future__ import annotations

import logging
import uuid

from flask import Blueprint, current_app, g, jsonify

from . import auth, authz, security, store, validation as v
from .db import get_db
from .errors import ApiError

bp = Blueprint("api", __name__)
security_log = logging.getLogger("nestack.security")


def _hash(password: str) -> str:
    cfg = current_app.extensions["cfg"]
    return security.hash_password(password, n=cfg.scrypt_n, r=cfg.scrypt_r, p=cfg.scrypt_p)


# ------------------------------------------------------------------ accounts

@bp.post("/register")
def register():
    data = v.read_json_object(required={"username", "password"}, reject_privilege_fields=True)
    username = v.validate_new_username(data["username"])
    password = v.validate_new_password(data["password"], username)
    try:
        user_id = store.create_user(get_db(), username, _hash(password), auth.now())
    except store.UsernameTaken:
        raise ApiError(409, "username already taken") from None
    security_log.info("user registered id=%s", user_id)
    return jsonify(id=user_id, username=username, role="user"), 201


@bp.post("/login")
def login():
    data = v.read_json_object(required={"username", "password"})
    raw_username = v.require_str(data["username"], "username", max_len=v.LOGIN_USERNAME_MAX)
    password = v.require_str(data["password"], "password", max_len=v.PASSWORD_MAX, allow_blank=True)

    username = v.normalise_username(raw_username)
    if username is None:
        # Can never be a real account. Don't create throttle rows for junk.
        auth.burn_hash(password)
        raise ApiError(401, "invalid credentials")

    user = auth.check_credentials(username, password)
    if user is None:
        raise ApiError(401, "invalid credentials")

    token, ttl = auth.issue_session(user["id"])
    return jsonify(token=token, token_type="Bearer", expires_in=ttl), 200


@bp.post("/logout")
@auth.require_auth
def logout():
    store.delete_session(get_db(), g.token_hash)
    return "", 204


@bp.get("/me")
@auth.require_auth
def me():
    return jsonify(id=g.user.id, username=g.user.username, role=g.user.role)


@bp.patch("/me")
@auth.require_auth
def update_me():
    """The only 'profile edit' is a password change. Any attempt to send a role
    (or other privilege field) is refused with 403 before anything else."""
    data = v.read_json_object(required={"current_password", "new_password"}, reject_privilege_fields=True)
    current = v.require_str(data["current_password"], "current_password", max_len=v.PASSWORD_MAX, allow_blank=True)
    new = v.validate_new_password(data["new_password"], g.user.username)

    # Goes through the same per-account throttle as /login, so a stolen session
    # cannot be used as an unthrottled password-guessing oracle.
    row = auth.check_credentials(g.user.username, current)
    if row is None or row["id"] != g.user.id:
        raise ApiError(403, "current password is incorrect")

    db = get_db()
    store.set_password_hash(db, g.user.id, _hash(new))
    store.delete_other_sessions(db, g.user.id, g.token_hash)   # kick out anyone else holding a session
    return jsonify(status="password updated")


# ------------------------------------------------------------------- records

@bp.post("/records")
@auth.require_auth
def create_record():
    data = v.read_json_object(required={"title", "body"})   # owner_id etc. -> 400, owner always = caller
    title = v.require_str(data["title"], "title", max_len=v.TITLE_MAX)
    body = v.require_str(data["body"], "body", max_len=v.BODY_MAX)
    record_id = uuid.uuid4().hex
    store.create_record(get_db(), record_id, g.user.id, title, body, auth.now())
    resp = jsonify(id=record_id, title=title)
    resp.status_code = 201
    resp.headers["Location"] = f"/records/{record_id}"
    return resp


@bp.get("/records/<record_id>")
@auth.require_auth
def read_record(record_id: str):
    not_found = ApiError(404, "record not found")

    # Malformed id, unknown id and someone-else's id all produce the SAME
    # response, so the API is not an oracle for which record ids exist.
    if not v.is_valid_record_id(record_id):
        raise not_found
    record = store.get_record(get_db(), record_id)
    if not authz.can_read_record(g.user, record):
        if record is not None:
            security_log.warning("access denied user=%s record=%s", g.user.id, record_id)
        raise not_found

    return jsonify(
        id=record["id"], owner_id=record["owner_id"], title=record["title"],
        body=record["body"], created_at=record["created_at"],
    )
