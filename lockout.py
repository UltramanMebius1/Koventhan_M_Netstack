"""Per-account brute-force protection.

Design points (all deliberate, all covered by tests/test_lockout.py):

* Keyed by normalised username, NOT by IP. Distributed guessing from many IPs
  against one account is therefore still throttled.
* Unknown usernames are tracked exactly like real ones, so "429 vs 401"
  cannot be used to discover which accounts exist.
* An attempt is *reserved before* the password is checked, inside a
  BEGIN IMMEDIATE transaction. Concurrent requests cannot all slip in under
  the limit: at most `max_failed_logins` guesses are ever evaluated per
  window, however many requests race.
* While locked, even the correct password gets 429. Otherwise the lock would
  not stop the attacker from eventually landing the right guess.
* Locks escalate (15 min, 30 min, 1 h ... capped at 24 h) for accounts that
  keep getting attacked, and forget old strikes after a quiet period.
* A successful login clears the state.

Trade-off, stated honestly in the README: anyone who knows a username can
lock that account out temporarily (availability for integrity). Escalation
is capped and locks expire.
"""
from __future__ import annotations

import sqlite3

from . import store
from .config import Config


def reserve_attempt(db: sqlite3.Connection, username: str, cfg: Config, now: int) -> int:
    """Return 0 if a login attempt may proceed, else the seconds until unlock."""
    db.execute("BEGIN IMMEDIATE")
    try:
        row = store.get_attempts(db, username)
        attempts = strikes = 0
        window_start = now

        if row is not None:
            if row["locked_until"] > now:
                db.execute("COMMIT")
                return int(row["locked_until"] - now)
            attempts, strikes, window_start = row["attempts"], row["strikes"], row["window_start"]
            last_activity = max(row["updated_at"], row["locked_until"])
            if now - last_activity > cfg.max_lockout_seconds:
                attempts, strikes, window_start = 0, 0, now       # quiet long enough: forgive
            elif now - window_start > cfg.failure_window_seconds:
                attempts, window_start = 0, now                    # stale window: keep strikes

        attempts += 1
        locked_until = 0
        if attempts >= cfg.max_failed_logins:
            # This is the last guess we will evaluate until the lock expires.
            strikes += 1
            duration = min(cfg.lockout_seconds * (2 ** min(strikes - 1, 30)), cfg.max_lockout_seconds)
            locked_until = now + duration
            attempts, window_start = 0, now

        store.save_attempts(db, username, attempts, window_start, locked_until, strikes, now)
        db.execute("COMMIT")
        return 0
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def clear(db: sqlite3.Connection, username: str) -> None:
    store.clear_attempts(db, username)
