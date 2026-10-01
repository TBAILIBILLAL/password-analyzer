"""Password history: a small database that lets the tool refuse old passwords.

Passwords themselves are never stored. For each account the database keeps a
random salt, and for each remembered password two salted, slow hashes
(PBKDF2-HMAC-SHA256): one of the password, and one of its "core" (its letters
in lowercase with look-alike substitutions undone). The first detects the same
password being used again; the second detects a small variation of an old one,
such as Summer2024! after Summer2023!.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import LEET

ITERATIONS = 200_000
KEEP = 10  # how many old passwords are remembered per account
_NOT_LETTERS = re.compile(r"[^a-z]")
_EDGES = re.compile(r"^[^a-z]+|[^a-z]+$")


def default_path() -> Path:
    """Where the history database lives unless PASSWORD_ANALYZER_DB says otherwise."""
    override = os.environ.get("PASSWORD_ANALYZER_DB")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA")
    folder = Path(base) / "PasswordAnalyzer" if base else Path.home() / ".password_analyzer"
    return folder / "history.db"


def core_of(password: str) -> str:
    """The letters of a password: lowercase, without the digits and symbols added at either
    end, and with substitutions like @ and 0 undone. Summer2023! and summer#99 both give "summer"."""
    trimmed = _EDGES.sub("", password.lower())
    return _NOT_LETTERS.sub("", trimmed.translate(LEET))


class PasswordHistory:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.execute("CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, salt BLOB NOT NULL)")
            con.execute(
                "CREATE TABLE IF NOT EXISTS history ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "account TEXT NOT NULL REFERENCES accounts(name) ON DELETE CASCADE, "
                "password_hash BLOB NOT NULL, "
                "core_hash BLOB, "
                "created_at TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA foreign_keys = ON")
        return con

    @staticmethod
    def _account(name: str) -> str:
        return name.strip().lower() or "default"

    @staticmethod
    def _hashes(password: str, salt: bytes) -> tuple[bytes, bytes | None]:
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
        core = core_of(password)
        # very short cores ("ab" in "ab12345!") would make unrelated passwords look alike
        core_hash = hashlib.pbkdf2_hmac("sha256", b"core:" + core.encode("utf-8"), salt, ITERATIONS) if len(core) >= 4 else None
        return password_hash, core_hash

    def _salt(self, con: sqlite3.Connection, account: str) -> bytes | None:
        row = con.execute("SELECT salt FROM accounts WHERE name = ?", (account,)).fetchone()
        return row[0] if row else None

    def check(self, account: str, password: str) -> str:
        """"exact" if the password is in the account's history, "similar" if a variation of it is, else "new"."""
        account = self._account(account)
        with closing(self._connect()) as con:
            salt = self._salt(con, account)
            if salt is None or not password:
                return "new"
            rows = con.execute("SELECT password_hash, core_hash FROM history WHERE account = ?", (account,)).fetchall()
        password_hash, core_hash = self._hashes(password, salt)
        if any(hmac.compare_digest(password_hash, stored) for stored, _ in rows):
            return "exact"
        if core_hash and any(stored and hmac.compare_digest(core_hash, stored) for _, stored in rows):
            return "similar"
        return "new"

    def add(self, account: str, password: str) -> None:
        """Remember a password as used. Only the newest KEEP passwords per account are kept."""
        if not password:
            raise ValueError("an empty password cannot be remembered")
        account = self._account(account)
        with closing(self._connect()) as con, con:
            salt = self._salt(con, account)
            if salt is None:
                salt = secrets.token_bytes(16)
                con.execute("INSERT INTO accounts (name, salt) VALUES (?, ?)", (account, salt))
            password_hash, core_hash = self._hashes(password, salt)
            con.execute(
                "INSERT INTO history (account, password_hash, core_hash, created_at) VALUES (?, ?, ?, ?)",
                (account, password_hash, core_hash, datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            con.execute(
                "DELETE FROM history WHERE account = ? AND id NOT IN "
                "(SELECT id FROM history WHERE account = ? ORDER BY id DESC LIMIT ?)",
                (account, account, KEEP),
            )

    def count(self, account: str) -> int:
        with closing(self._connect()) as con:
            return con.execute("SELECT COUNT(*) FROM history WHERE account = ?", (self._account(account),)).fetchone()[0]

    def dates(self, account: str) -> list[str]:
        """When each remembered password was added, newest first."""
        with closing(self._connect()) as con:
            rows = con.execute("SELECT created_at FROM history WHERE account = ? ORDER BY id DESC",
                               (self._account(account),)).fetchall()
        return [row[0] for row in rows]

    def clear(self, account: str) -> int:
        """Forget everything about an account. Returns how many passwords were removed."""
        account = self._account(account)
        with closing(self._connect()) as con, con:
            removed = con.execute("DELETE FROM history WHERE account = ?", (account,)).rowcount
            con.execute("DELETE FROM accounts WHERE name = ?", (account,))
        return removed
