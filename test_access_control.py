"""The core of the assessment: object-level authorization on every read."""
import re
import urllib.parse

import pytest


def test_owner_can_read_own_record(api):
    alice = api.user("alice")
    rid = api.create_record(alice, title="Q3 audit", body="very secret")
    r = api.get_record(alice, rid)
    assert r.status_code == 200
    assert r.get_json()["title"] == "Q3 audit"
    assert r.get_json()["body"] == "very secret"


def test_other_user_cannot_read_record(api):
    alice, bob = api.user("alice"), api.user("bob")
    rid = api.create_record(alice, body="alice-only-content")
    r = api.get_record(bob, rid)
    assert r.status_code in (403, 404)
    assert "alice-only-content" not in r.get_data(as_text=True)


def test_foreign_and_nonexistent_ids_are_indistinguishable(api):
    """No existence oracle: 'not yours' must look exactly like 'not there'."""
    alice, bob = api.user("alice"), api.user("bob")
    rid = api.create_record(alice)
    foreign = api.get_record(bob, rid)
    missing = api.get_record(bob, "0" * 32)
    malformed = api.get_record(bob, "not-an-id")
    assert foreign.status_code == missing.status_code == malformed.status_code == 404
    assert foreign.get_json() == missing.get_json() == malformed.get_json()


def test_denied_read_has_no_side_effects(api):
    alice, bob = api.user("alice"), api.user("bob")
    rid = api.create_record(alice, body="still here")
    assert api.get_record(bob, rid).status_code == 404
    assert api.get_record(alice, rid).get_json()["body"] == "still here"


def test_admin_can_read_any_record(api):
    alice, bob = api.user("alice"), api.user("bob")
    admin = api.make_admin("root-admin")
    ra, rb = api.create_record(alice, body="A"), api.create_record(bob, body="B")
    assert api.get_record(admin, ra).get_json()["body"] == "A"
    assert api.get_record(admin, rb).get_json()["body"] == "B"


def test_admin_gets_404_for_nonexistent_record(api):
    admin = api.make_admin("root-admin")
    assert api.get_record(admin, "f" * 32).status_code == 404


def test_each_user_only_sees_their_own_among_many(api):
    users = {n: api.user(n) for n in ("user1", "user2", "user3")}
    ids = {n: api.create_record(h, body=f"body-of-{n}") for n, h in users.items()}
    for reader, headers in users.items():
        for owner, rid in ids.items():
            r = api.get_record(headers, rid)
            if reader == owner:
                assert r.status_code == 200 and r.get_json()["body"] == f"body-of-{owner}"
            else:
                assert r.status_code == 404 and f"body-of-{owner}" not in r.get_data(as_text=True)


@pytest.mark.parametrize("headers", [
    {},                                         # no header
    {"Authorization": "Bearer"},                # no token
    {"Authorization": "Bearer not-a-token"},    # wrong shape
    {"Authorization": "Basic " + "A" * 43},     # wrong scheme
    {"Authorization": "Bearer " + "A" * 43},    # right shape, unknown token
])
def test_unauthenticated_requests_get_401(api, headers):
    alice = api.user("alice")
    rid = api.create_record(alice)
    assert api.get_record(headers, rid).status_code == 401
    assert api.client.post("/records", json={"title": "x", "body": "y"}, headers=headers).status_code == 401


def test_record_ids_are_random_not_sequential(api):
    alice = api.user("alice")
    ids = [api.create_record(alice) for _ in range(5)]
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    assert len(set(ids)) == 5


def test_client_cannot_choose_record_owner(api):
    """Mass assignment: owner is always the session user."""
    alice, bob = api.user("alice"), api.user("bob")
    bob_id = api.client.get("/me", headers=bob).get_json()["id"]
    r = api.client.post("/records", json={"title": "t", "body": "b", "owner_id": bob_id}, headers=alice)
    assert r.status_code == 400
    # and the normal path really does assign the caller
    rid = api.create_record(alice)
    assert api.get_record(alice, rid).get_json()["owner_id"] == api.client.get("/me", headers=alice).get_json()["id"]
    assert api.get_record(bob, rid).status_code == 404


@pytest.mark.parametrize("evil", [
    "1' OR '1'='1",
    "' OR 1=1 --",
    "x'; DROP TABLE records;--",
    "%27%20OR%20%271%27%3D%271",
    "../../etc/passwd",
])
def test_hostile_record_ids_do_not_leak_or_crash(api, evil):
    alice = api.user("alice")
    api.create_record(alice, body="must-not-leak")
    r = api.client.get("/records/" + urllib.parse.quote(evil, safe="%"), headers=alice)
    assert r.status_code in (404, 400)
    assert "must-not-leak" not in r.get_data(as_text=True)
    # table still intact
    assert api.client.post("/records", json={"title": "t", "body": "b"}, headers=alice).status_code == 201


def test_sql_metacharacters_in_content_are_stored_literally(api):
    alice = api.user("alice")
    nasty = "Robert'); DROP TABLE records;--"
    rid = api.create_record(alice, title=nasty, body=nasty)
    got = api.get_record(alice, rid).get_json()
    assert got["title"] == nasty and got["body"] == nasty


def test_sql_injection_in_login_username(api):
    api.user("alice")
    for payload in ("alice' OR '1'='1", "' OR 1=1 --", "alice'--"):
        r = api.client.post("/login", json={"username": payload, "password": "anything-at-all"})
        assert r.status_code == 401
