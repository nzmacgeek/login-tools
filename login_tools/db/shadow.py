"""
/etc/shadow reader and writer.

Format: username:hashed_password:lastchanged:min:max:warn:inactive:expire:reserved

Integer fields are represented as None in Python when the field is empty.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

from login_tools import paths
from login_tools.atomic import atomic_write_text, db_lock


def days_since_epoch() -> int:
    """Return the number of days since 1970-01-01 (Unix epoch)."""
    return (date.today() - date(1970, 1, 1)).days


def _int_or_none(s: str) -> int | None:
    return int(s) if s.strip() else None


def _opt_int_str(v: int | None) -> str:
    return str(v) if v is not None else ''


class ShadowNotFoundError(Exception):
    pass


@dataclass
class ShadowEntry:
    username: str
    hashed_password: str  # '!', '*', '!!', hash, or '!<hash>' (locked)
    last_changed: int | None  # days since epoch; 0 = must change now
    min_age: int | None
    max_age: int | None
    warn_days: int | None
    inactive_days: int | None
    expire_date: int | None   # days since epoch when account expires
    reserved: str             # always ''

    def to_line(self) -> str:
        return ':'.join([
            self.username,
            self.hashed_password,
            _opt_int_str(self.last_changed),
            _opt_int_str(self.min_age),
            _opt_int_str(self.max_age),
            _opt_int_str(self.warn_days),
            _opt_int_str(self.inactive_days),
            _opt_int_str(self.expire_date),
            self.reserved,
        ]) + '\n'

    @classmethod
    def from_line(cls, line: str) -> ShadowEntry:
        line = line.rstrip('\n')
        parts = line.split(':')
        if len(parts) < 8:
            raise ValueError(f'Invalid shadow line: {line!r}')
        # reserved field may be absent
        reserved = parts[8] if len(parts) > 8 else ''
        return cls(
            username=parts[0],
            hashed_password=parts[1],
            last_changed=_int_or_none(parts[2]),
            min_age=_int_or_none(parts[3]),
            max_age=_int_or_none(parts[4]),
            warn_days=_int_or_none(parts[5]),
            inactive_days=_int_or_none(parts[6]),
            expire_date=_int_or_none(parts[7]),
            reserved=reserved,
        )

    @classmethod
    def new_blank(cls, username: str) -> ShadowEntry:
        """Return a new shadow entry with no password set."""
        return cls(
            username=username,
            hashed_password='!!',
            last_changed=days_since_epoch(),
            min_age=0,
            max_age=99999,
            warn_days=7,
            inactive_days=None,
            expire_date=None,
            reserved='',
        )

    def is_locked(self) -> bool:
        """True if the account is shadow-locked (hash prefixed with '!' but not '!!', '!', or '*')."""
        h = self.hashed_password
        return h.startswith('!') and h not in ('!', '!!')

    def has_no_password(self) -> bool:
        """True if no real password has ever been set."""
        return self.hashed_password in ('!', '!!', '*', '')

    def must_change_password(self) -> bool:
        """True if the password must be changed at next login."""
        return self.last_changed == 0

    def is_expired(self) -> bool:
        """True if the account expiry date has passed."""
        if self.expire_date is None:
            return False
        return days_since_epoch() >= self.expire_date

    def is_password_expired(self) -> bool:
        """True if the password max age has been exceeded."""
        if self.max_age is None or self.last_changed is None:
            return False
        return days_since_epoch() >= self.last_changed + self.max_age


class ShadowDb:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or paths.shadow_path()

    def load(self) -> list[ShadowEntry]:
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            return []
        entries = []
        for line in text.splitlines():
            if line and not line.startswith('#'):
                try:
                    entries.append(ShadowEntry.from_line(line))
                except ValueError:
                    pass
        return entries

    def save(self, entries: list[ShadowEntry]) -> None:
        content = ''.join(e.to_line() for e in entries)
        atomic_write_text(self._path, content, mode=0o640)

    def get(self, username: str) -> ShadowEntry | None:
        for e in self.load():
            if e.username == username:
                return e
        return None

    def add(self, entry: ShadowEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            if any(e.username == entry.username for e in entries):
                raise ValueError(f'Shadow entry for {entry.username!r} already exists')
            entries.append(entry)
            self.save(entries)

    def remove(self, username: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            new_entries = [e for e in entries if e.username != username]
            if len(new_entries) == len(entries):
                raise ShadowNotFoundError(username)
            self.save(new_entries)

    def update(self, entry: ShadowEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.username == entry.username:
                    entries[i] = entry
                    self.save(entries)
                    return
            raise ShadowNotFoundError(entry.username)

    def set_password(self, username: str, hashed: str) -> None:
        """Update hash and record today as the last-changed date."""
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.username == username:
                    entries[i].hashed_password = hashed
                    entries[i].last_changed = days_since_epoch()
                    self.save(entries)
                    return
            raise ShadowNotFoundError(username)

    def lock(self, username: str) -> None:
        """Prepend '!' to the stored hash (locks the account).
        No-op if hash is '!', '!!', or '*' (has no password already)."""
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.username == username:
                    h = e.hashed_password
                    if h not in ('!', '!!', '*') and not h.startswith('!'):
                        entries[i].hashed_password = '!' + h
                        self.save(entries)
                    return
            raise ShadowNotFoundError(username)

    def unlock(self, username: str) -> None:
        """Remove leading '!' from a locked hash.
        No-op if hash is '!', '!!', or '*' (not a real locked hash)."""
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.username == username:
                    h = e.hashed_password
                    if h.startswith('!') and h not in ('!', '!!'):
                        entries[i].hashed_password = h[1:]
                        self.save(entries)
                    return
            raise ShadowNotFoundError(username)
