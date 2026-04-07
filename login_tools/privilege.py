"""
Privilege / UID helpers.
"""
from __future__ import annotations

import os
import sys


def get_effective_uid() -> int:
    return os.geteuid()


def is_root() -> bool:
    return get_effective_uid() == 0


def get_current_username() -> str:
    """Resolve effective UID to a username via the passwd database."""
    from login_tools.db.passwd import PasswdDb
    euid = get_effective_uid()
    entry = PasswdDb().get_by_uid(euid)
    if entry:
        return entry.username
    # Fall back to environment
    return os.environ.get('USER', os.environ.get('LOGNAME', 'unknown'))


def require_root(message: str = 'This operation requires root privileges.') -> None:
    """Print message to stderr and exit(1) if not running as root."""
    if not is_root():
        print(message, file=sys.stderr)
        sys.exit(1)


def drop_privileges(uid: int, gid: int) -> None:
    """
    Drop from root to the given uid/gid.
    Must set gid before uid, otherwise we lose the ability to setgid.
    """
    os.setgid(gid)
    os.setuid(uid)
