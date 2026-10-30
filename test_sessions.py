import re

from app.db import connect
from tests.conftest import PASSWORD


def test_token_is_opaque_random_and_unique(api):
    api.register("alice")
    t1, t2 = api.token("alice"), api.token("alice")
    assert t1 != t2
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", t1)
    assert "alice" not in t1 and "." not in t1           # not a JWT, encodes nothing


def test_login_response_shape(api):
    api.register("alice")
    body = api.login("alice").get_json()
    assert body["token_type"] == "Bearer" and body["expires_in"] > 0


def test_bad_credentials_are_401_and_uniform(api):
    api.register("alice")
    wrong_pw = api.login("alice", "not the password")
    no_user = api.login("nobody", "not the password")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.get_json() == no_user.get_json()     # same message: no user enumeration


def test_only_a_digest_of_the_token_is_stored(api, app):
    api.register("alice")
    token = api.token("alice")
    db = connect(app.extensions["cfg"].database_path)
    try:
        stored = [r["token_hash"] for r in db.execute("SELECT token_hash FROM sessions")]
    finally:
        db.close()
    assert stored and token not in stored
    assert all(re.fullmatch(r"[0-9a-f]{64}", s) for s in stored)


def test_tampered_or_forged_tokens_are_rejected(api):
    api.register("alice")
    token = api.token("alice")
    flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
    for bad in (flipped, token[:-1], token + "x", token.upper() if token.upper() != token else token.lower(), "A" * 43):
        r = api.client.get("/me", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401, bad
    assert api.client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_jwt_style_admin_forgery_is_rejected(api):
    """alg=none / hand-made claims mean nothing: there is nothing to forge."""
    import base64, json
    api.user("alice")
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    forged = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'alice', 'role': 'admin'})}."
    assert api.client.get("/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_session_expires(api, app):
    api.register("alice")
    h = {"Authorization": f"Bearer {api.token('alice')}"}
    assert api.client.get("/me", headers=h).status_code == 200
    app.config["CLOCK"].advance(app.extensions["cfg"].session_ttl_seconds + 1)
    assert api.client.get("/me", headers=h).status_code == 401


def test_logout_invalidates_the_token(api):
    h = api.user("alice")
    assert api.client.post("/logout", headers=h).status_code == 204
    assert api.client.get("/me", headers=h).status_code == 401


def test_logout_only_ends_that_session(api):
    api.register("alice")
    h1 = {"Authorization": f"Bearer {api.token('alice')}"}
    h2 = {"Authorization": f"Bearer {api.token('alice')}"}
    api.client.post("/logout", headers=h1)
    assert api.client.get("/me", headers=h2).status_code == 200


def test_password_change_revokes_other_sessions(api):
    api.register("alice")
    old = {"Authorization": f"Bearer {api.token('alice')}"}
    cur = {"Authorization": f"Bearer {api.token('alice')}"}
    r = api.client.patch("/me", json={"current_password": PASSWORD, "new_password": "a brand new passphrase"}, headers=cur)
    assert r.status_code == 200
    assert api.client.get("/me", headers=old).status_code == 401
    assert api.client.get("/me", headers=cur).status_code == 200
    assert api.login("alice", PASSWORD).status_code == 401
    assert api.login("alice", "a brand new passphrase").status_code == 200


def test_token_from_one_user_never_acts_as_another(api):
    ha, hb = api.user("alice"), api.user("bob")
    assert api.client.get("/me", headers=ha).get_json()["username"] == "alice"
    assert api.client.get("/me", headers=hb).get_json()["username"] == "bob"
