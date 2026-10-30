"""Authorization policy: the single place that decides who may read what.

Default deny. Adding a new resource type means adding a new function here and
a test in tests/test_access_control.py, not sprinkling ownership checks
through route handlers.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    id: int
    username: str
    role: str  # always read from the DB for the current request, never from the client

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def can_read_record(user: User, record) -> bool:
    if record is None:
        return False
    if user.role == "admin":
        return True
    return record["owner_id"] == user.id
