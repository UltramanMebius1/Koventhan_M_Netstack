import re

from app import security
from app.config import Config
from app.db import connect
from tests.conftest import PASSWORD

FAST = dict(n=2**4, r=8, p=1)


def test_hash_is_scrypt_salted_and_never_plaintext():
    h = security.hash_password("hunter2hunter2", **FAST)
    assert h.startswith("scrypt$16$8$1$")
    assert "hunter2" not in h
    assert re.fullmatch(r"scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+", h)


def test_same_password_gets_different_salt_and_hash():
    a, b = (security.hash_password("same password", **FAST) for _ in range(2))
    assert a != b
    assert a.split("$")[4] != b.split("$")[4]


def test_verify_roundtrip_and_rejection():
    h = security.hash_password("correct horse", **FAST)
    assert security.verify_password("correct horse", h)
    assert not security.verify_password("correct horsf", h)
    assert not security.verify_password("", h)


def test_verify_survives_garbage_stored_values():
    for junk in ("", "plaintext", "scrypt$x$y$z$a$b", "md5$1$1$1$AA==$AA==", "scrypt$16$8$1$!!$!!",
                 "scrypt$15$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA==",   # n not a power of 2
                 "scrypt$1073741824$32$16$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA=="):  # memory bomb
        assert security.verify_password("x", junk) is False


def test_unicode_passwords_work():
    h = security.hash_password("pässwörd-密码-🔐", **FAST)
    assert security.verify_password("pässwörd-密码-🔐", h)


def test_production_defaults_meet_owasp_scrypt_guidance():
    cfg = Config()
    assert cfg.scrypt_r == 8
    # OWASP-equivalent minimums: (2^17,1) (2^16,2) (2^15,3) (2^14,5)
    assert (cfg.scrypt_n, cfg.scrypt_p) in {(2**17, 1), (2**16, 2), (2**15, 3), (2**14, 5)} or \
        cfg.scrypt_n * cfg.scrypt_p >= 2**17


def test_env_cannot_weaken_scrypt_below_floor(monkeypatch):
    import pytest
    monkeypatch.setenv("SCRYPT_N", "1024")
    with pytest.raises(RuntimeError):
        Config.from_env()
    monkeypatch.setenv("SCRYPT_N", "20000")   # not a power of two
    with pytest.raises(RuntimeError):
        Config.from_env()


def test_database_never_contains_the_plaintext_password(api, app):
    api.register("alice", "my very secret passphrase")
    db = connect(app.extensions["cfg"].database_path)
    try:
        row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    finally:
        db.close()
    assert row["password_hash"].startswith("scrypt$")
    assert "my very secret passphrase" not in row["password_hash"]
    with open(app.extensions["cfg"].database_path, "rb") as fh:
        assert b"my very secret passphrase" not in fh.read()


def test_two_users_same_password_have_different_stored_hashes(api, app):
    api.register("alice", PASSWORD)
    api.register("bob", PASSWORD)
    db = connect(app.extensions["cfg"].database_path)
    try:
        hashes = [r[0] for r in db.execute("SELECT password_hash FROM users ORDER BY id")]
    finally:
        db.close()
    assert hashes[0] != hashes[1]


def test_login_for_unknown_user_still_does_a_hash(api, monkeypatch):
    """Timing equalisation: the 'no such user' path must burn a real scrypt."""
    from app import auth
    calls = []
    real = auth.security.verify_password
    monkeypatch.setattr(auth.security, "verify_password", lambda pw, stored: calls.append(1) or real(pw, stored))
    assert api.login("ghost", "whatever-password").status_code == 401
    assert len(calls) == 1
