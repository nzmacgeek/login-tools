"""
/etc/group reader and writer.

Format: groupname:password:gid:members
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from login_tools import paths
from login_tools.atomic import atomic_write_text, db_lock

SYSTEM_GID_MAX = 999
GROUP_GID_MIN = 1000
GROUP_GID_MAX = 60000

GROUPNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')


class GroupExistsError(Exception):
    pass


class GroupNotFoundError(Exception):
    pass


class GIDInUseError(Exception):
    pass


@dataclass
class GroupEntry:
    groupname: str
    password: str       # 'x' or '*'
    gid: int
    members: list[str] = field(default_factory=list)

    def to_line(self) -> str:
        return f'{self.groupname}:{self.password}:{self.gid}:{",".join(self.members)}\n'

    @classmethod
    def from_line(cls, line: str) -> GroupEntry:
        line = line.rstrip('\n')
        parts = line.split(':')
        if len(parts) < 3:
            raise ValueError(f'Invalid group line: {line!r}')
        members_str = parts[3] if len(parts) > 3 else ''
        members = [m for m in members_str.split(',') if m]
        return cls(
            groupname=parts[0],
            password=parts[1],
            gid=int(parts[2]),
            members=members,
        )


class GroupDb:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or paths.group_path()

    def load(self) -> list[GroupEntry]:
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            return []
        entries = []
        for line in text.splitlines():
            if line and not line.startswith('#'):
                try:
                    entries.append(GroupEntry.from_line(line))
                except ValueError:
                    pass
        return entries

    def save(self, entries: list[GroupEntry]) -> None:
        content = ''.join(e.to_line() for e in entries)
        atomic_write_text(self._path, content, mode=0o644)

    def get_by_name(self, groupname: str) -> GroupEntry | None:
        for e in self.load():
            if e.groupname == groupname:
                return e
        return None

    def get_by_gid(self, gid: int) -> GroupEntry | None:
        for e in self.load():
            if e.gid == gid:
                return e
        return None

    def all_entries(self) -> list[GroupEntry]:
        return self.load()

    def add(self, entry: GroupEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            if any(e.groupname == entry.groupname for e in entries):
                raise GroupExistsError(entry.groupname)
            if any(e.gid == entry.gid for e in entries):
                raise GIDInUseError(str(entry.gid))
            entries.append(entry)
            self.save(entries)

    def remove(self, groupname: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            new_entries = [e for e in entries if e.groupname != groupname]
            if len(new_entries) == len(entries):
                raise GroupNotFoundError(groupname)
            self.save(new_entries)

    def update(self, entry: GroupEntry) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.groupname == entry.groupname:
                    entries[i] = entry
                    self.save(entries)
                    return
            raise GroupNotFoundError(entry.groupname)

    def add_member(self, groupname: str, username: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.groupname == groupname:
                    if username not in e.members:
                        entries[i].members.append(username)
                        self.save(entries)
                    return
            raise GroupNotFoundError(groupname)

    def remove_member(self, groupname: str, username: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if e.groupname == groupname:
                    if username in e.members:
                        entries[i].members = [m for m in e.members if m != username]
                        self.save(entries)
                    return
            raise GroupNotFoundError(groupname)

    def groups_for_user(self, username: str) -> list[GroupEntry]:
        return [e for e in self.load() if username in e.members]

    def remove_user_from_all_groups(self, username: str) -> None:
        with db_lock(self._path):
            entries = self.load()
            for i, e in enumerate(entries):
                if username in e.members:
                    entries[i].members = [m for m in e.members if m != username]
            self.save(entries)

    def next_gid(self, system: bool = False) -> int:
        entries = self.load()
        used = {e.gid for e in entries}
        if system:
            gid_min, gid_max = 1, SYSTEM_GID_MAX
        else:
            gid_min, gid_max = GROUP_GID_MIN, GROUP_GID_MAX
        for gid in range(gid_min, gid_max + 1):
            if gid not in used:
                return gid
        raise RuntimeError(f'No available GIDs in range {gid_min}..{gid_max}')

    def is_primary_group_of_any_user(self, gid: int, passwd_db: object) -> bool:
        """Return True if any user in passwd_db has this gid as their primary group."""
        for e in passwd_db.all_entries():  # type: ignore[attr-defined]
            if e.gid == gid:
                return True
        return False

    @staticmethod
    def validate_groupname(groupname: str) -> None:
        if not GROUPNAME_RE.match(groupname):
            raise ValueError(
                f'Invalid groupname {groupname!r}: must match ^[a-z_][a-z0-9_-]{{0,31}}$'
            )
