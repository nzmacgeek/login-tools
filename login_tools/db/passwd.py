"""
/etc/passwd reader and writer.

Format: username:x:uid:gid:gecos:home:shell
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from login_tools import paths
from login_tools.atomic import atomic_write_text, db_lock

USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SYSTEM_UID_MAX = 999
USER_UID_MIN = 1000
USER_UID_MAX = 60000


class UserExistsError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class UIDInUseError(Exception):
    pass


@dataclass
class PasswdEntry:
    username: str
    password: str   # always 'x' (shadow is used)
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str

    def to_line(self) -> str:
        gecos = self.gecos.replace(':', ' ')  # colons are field separators
        return f'{self.username}:{self.password}:{self.uid}:{self.gid}:{gecos}:{self.home}:{self.shell}\n'

    @classmethod
    def from_line(cls, line: str) -> PasswdEntry:
        line = line.rstrip('\n')
        parts = line.split(':')
        if len(parts) != 7:
            raise ValueError(f'Invalid passwd line: {line!r}')
        return cls(
            username=parts[0],
            password=parts[1],
            uid=int(parts[2]),
            gid=int(parts[3]),
            gecos=parts[4],
            home=parts[5],
            shell=parts[6],
        )


class PasswdDb:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or paths.passwd_path()

    def load(self) -> list[PasswdEntry]:
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            return []
        entries = []
        for line in text.splitlines():
            if line and not line.startswith('#'):
                try:
                    entries.append(PasswdEntry.from_line(line))
                except ValueError:
                    pass
        return entries

    def save(self, entries: list[PasswdEntry]) -> None:
        content = ''.join(e.to_line() for e in entries)
        atomic_write_text(self._path, content, mode=0o644)

    def get_by_name(self, username: str) -> PasswdEntry | None:
        for e in self.load():
            if e.username == username:
                return e
        return None

    def get_by_uid(self, uid: int) -> PasswdEntry | None:
        for e in self.load():
            if e.uid == uid:
                return e
        return None

    def all_entries(self) -> list[PasswdEntry]:
        return self.load()

    def add(self, entry: PasswdEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            if any(e.username == entry.username for e in entries):
                raise UserExistsError(entry.username)
            if any(e.uid == entry.uid for e in entries):
                raise UIDInUseError(str(entry.uid))
            entries.append(entry)
            self.save(entries)

    def remove(self, username: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            new_entries = [e for e in entries if e.username != username]
            if len(new_entries) == len(entries):
                raise UserNotFoundError(username)
            self.save(new_entries)

    def update(self, entry: PasswdEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.username == entry.username:
                    entries[i] = entry
                    self.save(entries)
                    return
            raise UserNotFoundError(entry.username)

    def next_uid(self, system: bool = False) -> int:
        """Find the next available UID in the appropriate range."""
        entries = self.load()
        used = {e.uid for e in entries}
        if system:
            uid_min, uid_max = 1, SYSTEM_UID_MAX
        else:
            uid_min, uid_max = USER_UID_MIN, USER_UID_MAX
        for uid in range(uid_min, uid_max + 1):
            if uid not in used:
                return uid
        raise RuntimeError(f'No available UIDs in range {uid_min}..{uid_max}')

    @staticmethod
    def validate_username(username: str) -> None:
        """Raise ValueError if the username fails the naming rules."""
        if not USERNAME_RE.match(username):
            raise ValueError(
                f'Invalid username {username!r}: must match ^[a-z_][a-z0-9_-]{{0,31}}$'
            )
