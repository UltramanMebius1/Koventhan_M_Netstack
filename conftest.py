import dataclasses

import pytest

from app import create_app, security, store
from app.config import Config
from app.db import connect

# Cheap scrypt for tests only (production default is N=2**15, p=3).
FAST = dict(scrypt_n=2**4, scrypt_r=8, scrypt_p=1)


class FakeClock:
    def __init__(self, start=1_700_000_000):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def make_app(tmp_path):
    def _make(**overrides):
        cfg = dataclasses.replace(Config(), database_path=str(tmp_path / "test.db"), **FAST, **overrides)
        app = create_app(cfg)
        app.config["CLOCK"] = FakeClock()
        app.config["TESTING"] = True
        return app
    return _make


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()


PASSWORD = "correct horse battery"


class Api:
    """Tiny helper so tests read like scenarios."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()

    def register(self, username, password=PASSWORD):
        return self.client.post("/register", json={"username": username, "password": password})

    def login(self, username, password=PASSWORD):
        return self.client.post("/login", json={"username": username, "password": password})

    def token(self, username, password=PASSWORD):
        r = self.login(username, password)
        assert r.status_code == 200, r.get_data(as_text=True)
        return r.get_json()["token"]

    def user(self, username):
        """Register + log in. Returns auth headers."""
        assert self.register(username).status_code == 201
        return {"Authorization": f"Bearer {self.token(username)}"}

    def make_admin(self, username, password=PASSWORD):
        """Admins are created out-of-band (as the CLI does), never via HTTP."""
        cfg = self.app.extensions["cfg"]
        db = connect(cfg.database_path)
        try:
            store.create_admin(
                db, username,
                security.hash_password(password, n=cfg.scrypt_n, r=cfg.scrypt_r, p=cfg.scrypt_p), 0,
            )
        finally:
            db.close()
        return {"Authorization": f"Bearer {self.token(username, password)}"}

    def set_role_in_db(self, username, role):
        cfg = self.app.extensions["cfg"]
        db = connect(cfg.database_path)
        try:
            db.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        finally:
            db.close()

    def create_record(self, headers, title="t", body="b"):
        r = self.client.post("/records", json={"title": title, "body": body}, headers=headers)
        assert r.status_code == 201, r.get_data(as_text=True)
        return r.get_json()["id"]

    def get_record(self, headers, record_id):
        return self.client.get(f"/records/{record_id}", headers=headers)


@pytest.fixture
def api(app):
    return Api(app)
