"""Every SQL statement in the application lives in this file.

Rule: statements are constant strings; user-controlled values only ever travel
as bound parameters (`?`). There is no string formatting/concatenation of SQL
anywhere (tests/test_validation.py greps for it).
"""
from __future__ import annotations

import sqlite3
from typing import Optional


class UsernameTaken(Exception):
    pass


# --------------------------------------------------------------------- users

def create_user(db: sqlite3.Connection, username: str, password_hash: str, now: int) -> int:
    """Used by POST /register. The role is a SQL literal: nothing a client
    sends can influence it."""
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'user', ?)",
            (username, password_hash, now),
        )
    except sqlite3.IntegrityError:
        raise UsernameTaken() from None
    return int(cur.lastrowid)


def create_admin(db: sqlite3.Connection, username: str, password_hash: str, now: int) -> int:
    """Only reachable from the CLI (app/cli.py) and tests. There is no HTTP
    route that calls this."""
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'admin', ?)",
            (username, password_hash, now),
        )
    except sqlite3.IntegrityError:
        raise UsernameTaken() from None
    return int(cur.lastrowid)


def get_user_by_username(db: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def set_password_hash(db: sqlite3.Connection, user_id: int, password_hash: str) -> None:
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


# ------------------------------------------------------------------ sessions

def create_session(db: sqlite3.Connection, token_hash: str, user_id: int, now: int, expires_at: int) -> None:
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token_hash, user_id, now, expires_at),
    )


def get_session_user(db: sqlite3.Connection, token_hash: str, now: int) -> Optional[sqlite3.Row]:
    """Resolve a session to its user. Role is read from the users table on every
    request, so it is never stale and never client-supplied."""
    return db.execute(
        "SELECT u.id AS id, u.username AS username, u.role AS role "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (token_hash, now),
    ).fetchone()


def delete_session(db: sqlite3.Connection, token_hash: str) -> None:
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_other_sessions(db: sqlite3.Connection, user_id: int, keep_token_hash: str) -> None:
    db.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?",
        (user_id, keep_token_hash),
    )


def purge_expired_sessions(db: sqlite3.Connection, now: int) -> None:
    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))


# ------------------------------------------------------------------- records

def create_record(db: sqlite3.Connection, record_id: str, owner_id: int, title: str, body: str, now: int) -> None:
    db.execute(
        "INSERT INTO records (id, owner_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (record_id, owner_id, title, body, now),
    )


def get_record(db: sqlite3.Connection, record_id: str) -> Optional[sqlite3.Row]:
    """Fetch by id only. The ownership decision is NOT made here; it is made
    in authz.can_read_record so there is exactly one place to audit."""
    return db.execute(
        "SELECT id, owner_id, title, body, created_at FROM records WHERE id = ?",
        (record_id,),
    ).fetchone()


# ------------------------------------------------------------ login throttle

def get_attempts(db: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return db.execute(
        "SELECT attempts, window_start, locked_until, strikes, updated_at "
        "FROM login_attempts WHERE username = ?",
        (username,),
    ).fetchone()


def save_attempts(db: sqlite3.Connection, username: str, attempts: int, window_start: int,
                  locked_until: int, strikes: int, now: int) -> None:
    db.execute(
        "INSERT INTO login_attempts (username, attempts, window_start, locked_until, strikes, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET "
        "attempts = excluded.attempts, window_start = excluded.window_start, "
        "locked_until = excluded.locked_until, strikes = excluded.strikes, "
        "updated_at = excluded.updated_at",
        (username, attempts, window_start, locked_until, strikes, now),
    )


def clear_attempts(db: sqlite3.Connection, username: str) -> None:
    db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))


def purge_stale_attempts(db: sqlite3.Connection, now: int, decay_seconds: int) -> None:
    """Bound table growth (attackers can feed us arbitrary well-formed names)."""
    db.execute(
        "DELETE FROM login_attempts WHERE locked_until <= ? AND updated_at <= ?",
        (now, now - decay_seconds),
    )
