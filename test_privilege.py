"""A user must never be able to become admin; role is assigned server-side only."""
import pytest

from tests.conftest import PASSWORD


@pytest.mark.parametrize("key", ["role", "Role", "roles", "is_admin", "isAdmin", "is-admin", "admin", "permissions"])
@pytest.mark.parametrize("value", ["admin", True, ["admin"], 1])
def test_register_with_privilege_field_is_refused(api, key, value):
    r = api.client.post("/register", json={"username": "mallory", "password": PASSWORD, key: value})
    assert r.status_code == 403
    # ...and no account was created as a side effect
    assert api.register("mallory").status_code == 201


def test_registered_account_is_always_a_plain_user(api):
    r = api.register("alice")
    assert r.status_code == 201
    assert r.get_json()["role"] == "user"
    headers = {"Authorization": f"Bearer {api.token('alice')}"}
    assert api.client.get("/me", headers=headers).get_json()["role"] == "user"


def test_user_cannot_escalate_via_profile_edit(api):
    alice, bob = api.user("alice"), api.user("bob")
    rid = api.create_record(bob, body="bob-private")

    for payload in (
        {"role": "admin"},
        {"current_password": PASSWORD, "new_password": "another pass 123", "role": "admin"},
        {"current_password": PASSWORD, "new_password": "another pass 123", "isAdmin": True},
    ):
        r = api.client.patch("/me", json=payload, headers=alice)
        assert r.status_code == 403

    assert api.client.get("/me", headers=alice).get_json()["role"] == "user"
    assert api.get_record(alice, rid).status_code == 404       # still no admin powers
    # and the password was NOT changed by the refused requests
    assert api.login("alice", PASSWORD).status_code == 200


def test_there_is_no_http_route_that_creates_admins(app):
    """Defence in depth: enumerate every route; none besides these exist."""
    rules = {(m, r.rule) for r in app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"}}
    assert rules == {
        ("POST", "/register"), ("POST", "/login"), ("POST", "/logout"),
        ("GET", "/me"), ("PATCH", "/me"),
        ("POST", "/records"), ("GET", "/records/<record_id>"),
    }


def test_role_is_read_from_db_on_each_request_not_baked_into_token(api):
    """Because tokens are opaque, a role change takes effect immediately and a
    client cannot carry a stale (or forged) claim."""
    alice, bob = api.user("alice"), api.user("bob")
    rid = api.create_record(bob)
    assert api.get_record(alice, rid).status_code == 404
    api.set_role_in_db("alice", "admin")            # out-of-band promotion (operator action)
    assert api.get_record(alice, rid).status_code == 200
    api.set_role_in_db("alice", "user")             # demotion
    assert api.get_record(alice, rid).status_code == 404


def test_db_rejects_invalid_roles(api):
    import sqlite3
    api.register("alice")
    with pytest.raises(sqlite3.IntegrityError):
        api.set_role_in_db("alice", "superuser")


def test_cli_creates_admin(tmp_path, monkeypatch, make_app, capsys):
    from app import cli
    app = make_app()
    cfg = app.extensions["cfg"]
    monkeypatch.setenv("DATABASE_PATH", cfg.database_path)
    monkeypatch.setenv("SCRYPT_N", str(2**14))   # env floor
    monkeypatch.setenv("SCRYPT_P", "1")
    import io, sys
    monkeypatch.setattr(sys, "stdin", io.StringIO("an admin passphrase\n"))
    assert cli.main(["create-admin", "boss", "--password-stdin"]) == 0
    c = app.test_client()
    tok = c.post("/login", json={"username": "boss", "password": "an admin passphrase"}).get_json()["token"]
    assert c.get("/me", headers={"Authorization": f"Bearer {tok}"}).get_json()["role"] == "admin"
