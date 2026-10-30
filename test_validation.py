import json
import pathlib
import re

import pytest

from tests.conftest import PASSWORD

GOOD = {"username": "alice", "password": PASSWORD}


def assert_clean_400(resp):
    assert resp.status_code == 400, resp.get_data(as_text=True)
    text = resp.get_data(as_text=True)
    assert "Traceback" not in text and "File \"" not in text
    assert resp.is_json and "error" in resp.get_json()


@pytest.mark.parametrize("payload", [
    {}, {"username": "alice"}, {"password": PASSWORD},
    {"username": 123, "password": PASSWORD},
    {"username": ["alice"], "password": PASSWORD},
    {"username": None, "password": PASSWORD},
    {"username": True, "password": PASSWORD},
    {"username": "alice", "password": 12345678},
    {"username": "alice", "password": None},
    {"username": "alice", "password": {"a": 1}},
    {"username": "al", "password": PASSWORD},                      # too short
    {"username": "a" * 33, "password": PASSWORD},                  # too long
    {"username": "ali ce", "password": PASSWORD},                  # bad chars
    {"username": "alice\n", "password": PASSWORD},                 # trailing newline must not slip past regex
    {"username": "алиса", "password": PASSWORD},                   # non-ascii
    {"username": "alice", "password": "short"},
    {"username": "alice", "password": "x" * 129},
    {"username": "alice", "password": "          "},               # blank
    {"username": "alice", "password": "alice"},                    # password == username (too short anyway)
    {"username": "alice", "password": PASSWORD, "extra": 1},       # unknown field
])
def test_register_rejects_bad_input(client, payload):
    assert_clean_400(client.post("/register", json=payload))


def test_register_rejects_lone_surrogates(client):
    raw = '{"username": "alice", "password": "pass\\ud800word123"}'
    assert_clean_400(client.post("/register", data=raw, content_type="application/json"))


@pytest.mark.parametrize("payload", [
    {}, {"username": "alice"}, {"password": PASSWORD},
    {"username": 1, "password": PASSWORD}, {"username": "alice", "password": 1},
    {"username": "alice", "password": ""}, {"username": "a" * 65, "password": PASSWORD},
    {"username": "alice", "password": "x" * 129},
])
def test_login_rejects_bad_input(client, payload):
    assert_clean_400(client.post("/login", json=payload))


@pytest.mark.parametrize("payload", [
    {}, {"title": "t"}, {"body": "b"},
    {"title": 1, "body": "b"}, {"title": "t", "body": 1}, {"title": None, "body": "b"},
    {"title": ["t"], "body": "b"}, {"title": "t", "body": {"x": 1}}, {"title": False, "body": "b"},
    {"title": "", "body": "b"}, {"title": "   ", "body": "b"}, {"title": "t", "body": ""},
    {"title": "t" * 201, "body": "b"}, {"title": "t", "body": "b" * 10_001},
    {"title": "t", "body": "b", "owner_id": 1}, {"title": "t", "body": "b", "id": "x"},
])
def test_create_record_rejects_bad_input(api, payload):
    h = api.user("alice")
    assert_clean_400(api.client.post("/records", json=payload, headers=h))


def test_create_record_accepts_max_sizes(api):
    h = api.user("alice")
    r = api.client.post("/records", json={"title": "t" * 200, "body": "b" * 10_000}, headers=h)
    assert r.status_code == 201


@pytest.mark.parametrize("kwargs", [
    dict(data="{not json", content_type="application/json"),
    dict(data="", content_type="application/json"),
    dict(data="null", content_type="application/json"),
    dict(data="[]", content_type="application/json"),
    dict(data='"a string"', content_type="application/json"),
    dict(data="42", content_type="application/json"),
    dict(data=json.dumps(GOOD), content_type="text/plain"),            # wrong content type
    dict(data=json.dumps(GOOD), content_type="application/x-www-form-urlencoded"),
    dict(data=b"\xff\xfe\x00garbage", content_type="application/json"),  # invalid UTF-8
    dict(data="[" * 20000 + "]" * 20000, content_type="application/json"),  # deep nesting
])
def test_malformed_bodies_are_400_not_500(client, kwargs):
    for path in ("/register", "/login"):
        assert_clean_400(client.post(path, **kwargs))


def test_oversized_body_is_400(client, app):
    limit = app.extensions["cfg"].max_body_bytes
    big = json.dumps({"username": "alice", "password": PASSWORD, "pad": "x" * (limit + 10)})
    assert_clean_400(client.post("/register", data=big, content_type="application/json"))


def test_oversized_body_on_authenticated_route(api, app):
    h = api.user("alice")
    limit = app.extensions["cfg"].max_body_bytes
    big = json.dumps({"title": "t", "body": "x" * (limit + 10)})
    assert_clean_400(api.client.post("/records", data=big, content_type="application/json", headers=h))


def test_duplicate_username_is_409_and_case_insensitive(api):
    assert api.register("alice").status_code == 201
    assert api.register("alice").status_code == 409
    assert api.register("ALICE").status_code == 409


def test_unexpected_errors_return_generic_500_without_stack_trace(app, client, monkeypatch):
    from app import routes

    def boom(*a, **k):
        raise RuntimeError("secret internal detail /srv/app/db.py")
    monkeypatch.setattr(routes.store, "create_user", boom)
    r = client.post("/register", json=GOOD)
    assert r.status_code == 500
    text = r.get_data(as_text=True)
    assert "secret internal detail" not in text and "Traceback" not in text
    assert r.get_json() == {"error": "internal server error"}


def test_unknown_routes_and_methods_are_json(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.is_json
    r = client.delete("/records/abc")
    assert r.status_code == 405 and r.is_json


def test_security_headers_present(client):
    r = client.post("/login", json={"username": "x", "password": "y"})
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_no_string_built_sql_anywhere():
    """Cheap tripwire for the 'Injection' rule: no f-string / %-format /
    .format() / concatenation in anything handed to .execute()."""
    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    offenders = []
    for path in root.glob("*.py"):
        src = path.read_text()
        for m in re.finditer(r"\.execute(?:many|script)?\(\s*(.*)", src):
            first = m.group(1)
            if re.match(r"""(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format))""", first):
                offenders.append(f"{path.name}: {first[:60]}")
    assert offenders == []
