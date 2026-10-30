import threading

from tests.conftest import PASSWORD


def bad(api, username, n=1):
    return [api.login(username, "wrong password!").status_code for _ in range(n)]


def test_five_failures_then_429(api):
    api.register("alice")
    assert bad(api, "alice", 5) == [401] * 5
    r = api.login("alice", "wrong password!")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


def test_correct_password_is_also_refused_while_locked(api):
    api.register("alice")
    bad(api, "alice", 5)
    assert api.login("alice", PASSWORD).status_code == 429


def test_lock_expires(api, app):
    api.register("alice")
    bad(api, "alice", 5)
    assert api.login("alice", PASSWORD).status_code == 429
    app.config["CLOCK"].advance(app.extensions["cfg"].lockout_seconds + 1)
    assert api.login("alice", PASSWORD).status_code == 200


def test_lockout_is_per_account_not_per_ip(api):
    """Same client (same IP) hammers alice; bob is unaffected."""
    api.register("alice")
    api.register("bob")
    bad(api, "alice", 6)
    assert api.login("alice", PASSWORD).status_code == 429
    assert api.login("bob", PASSWORD).status_code == 200


def test_lockout_follows_the_account_across_clients(api, app):
    """Different 'IPs'/clients share the same per-account counter."""
    api.register("alice")
    for i in range(5):
        c = app.test_client()
        r = c.post("/login", json={"username": "alice", "password": "wrong password!"},
                   environ_overrides={"REMOTE_ADDR": f"10.0.0.{i}"})
        assert r.status_code == 401
    c = app.test_client()
    r = c.post("/login", json={"username": "alice", "password": PASSWORD},
               environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
    assert r.status_code == 429


def test_username_case_cannot_dodge_the_lock(api):
    api.register("alice")
    for name in ("alice", "ALICE", "Alice", "aLiCe", "alice"):
        assert api.login(name, "wrong password!").status_code == 401
    assert api.login("ALICE", PASSWORD).status_code == 429


def test_unknown_usernames_are_throttled_identically(api):
    """No enumeration through the throttle: ghost accounts lock like real ones."""
    assert bad(api, "ghost", 5) == [401] * 5
    assert api.login("ghost", "wrong password!").status_code == 429


def test_success_resets_the_counter(api):
    api.register("alice")
    bad(api, "alice", 4)
    assert api.login("alice", PASSWORD).status_code == 200
    assert bad(api, "alice", 4) == [401] * 4       # would have been locked without the reset
    assert api.login("alice", PASSWORD).status_code == 200


def test_old_failures_age_out_of_the_window(api, app):
    api.register("alice")
    bad(api, "alice", 4)
    app.config["CLOCK"].advance(app.extensions["cfg"].failure_window_seconds + 1)
    assert bad(api, "alice", 4) == [401] * 4


def test_repeat_offenders_get_longer_locks(api, app):
    api.register("alice")
    cfg = app.extensions["cfg"]
    bad(api, "alice", 5)
    first = int(api.login("alice", PASSWORD).headers["Retry-After"])
    app.config["CLOCK"].advance(first + 1)
    bad(api, "alice", 5)
    second = int(api.login("alice", PASSWORD).headers["Retry-After"])
    assert first <= cfg.lockout_seconds
    assert second > first


def test_concurrent_guesses_cannot_exceed_the_limit(make_app):
    """Attempts are reserved before verification inside BEGIN IMMEDIATE, so a
    burst of parallel guesses cannot all squeeze in under the threshold."""
    app = make_app()
    from tests.conftest import Api
    api = Api(app)
    api.register("alice")
    results = []

    def attempt():
        c = app.test_client()
        results.append(c.post("/login", json={"username": "alice", "password": "wrong password!"}).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(401) <= app.extensions["cfg"].max_failed_logins
    assert results.count(429) >= 20 - app.extensions["cfg"].max_failed_logins
    assert 500 not in results


def test_password_change_endpoint_is_throttled_too(api):
    """A stolen session must not become an unthrottled password oracle."""
    h = api.user("alice")
    codes = [
        api.client.patch("/me", json={"current_password": "wrong password!", "new_password": "brand new pass 1"},
                         headers=h).status_code
        for _ in range(6)
    ]
    assert codes[:5] == [403] * 5 and codes[5] == 429
    assert api.login("alice", PASSWORD).status_code == 429
