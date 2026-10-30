"""Out-of-band administration. Admins can ONLY be created here (or by someone
who already has write access to the database file); no HTTP route can do it.

    python -m app.cli create-admin alice            # prompts for the password
    printf '%s' "$PW" | python -m app.cli create-admin alice --password-stdin
"""
from __future__ import annotations

import argparse
import getpass
import sys
import time

from . import security, store, validation
from .config import Config
from .db import connect, init_db
from .errors import ApiError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create-admin", help="create a new admin account")
    p.add_argument("username")
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    args = parser.parse_args(argv)

    cfg = Config.from_env()
    try:
        username = validation.validate_new_username(args.username)
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Repeat password: "):
                print("passwords do not match", file=sys.stderr)
                return 1
        password = validation.validate_new_password(password, username)
    except ApiError as err:
        print(f"error: {err.message}", file=sys.stderr)
        return 1

    init_db(cfg.database_path)
    pw_hash = security.hash_password(password, n=cfg.scrypt_n, r=cfg.scrypt_r, p=cfg.scrypt_p)
    db = connect(cfg.database_path)
    try:
        store.create_admin(db, username, pw_hash, int(time.time()))
    except store.UsernameTaken:
        print("error: username already exists", file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"admin '{username}' created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
