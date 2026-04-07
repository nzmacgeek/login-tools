"""
userdel: Delete a user account.

Usage: userdel [-r] [-f] username
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from login_tools.db.group import GroupDb
from login_tools.db.passwd import PasswdDb, UserNotFoundError
from login_tools.db.shadow import ShadowDb, ShadowNotFoundError
from login_tools.faillock import FailLock
from login_tools.privilege import require_root


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='userdel', description='Delete a user account.')
    parser.add_argument('username')
    parser.add_argument('-r', '--remove', action='store_true',
                        help='Remove home directory and mail spool')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Force removal even if user appears to be logged in')
    args = parser.parse_args()

    username = args.username
    pdb = PasswdDb()
    sdb = ShadowDb()
    gdb = GroupDb()

    entry = pdb.get_by_name(username)
    if entry is None:
        print(f'userdel: user {username!r} not found.', file=sys.stderr)
        sys.exit(3)

    # Remove from all supplementary groups
    gdb.remove_user_from_all_groups(username)

    # Remove home directory if requested
    if args.remove and entry.home and entry.home != '/':
        home_path = Path(entry.home)
        if home_path.exists():
            try:
                shutil.rmtree(home_path)
            except OSError as exc:
                print(f'userdel: warning: could not remove {home_path}: {exc}', file=sys.stderr)

    # Remove passwd entry
    try:
        pdb.remove(username)
    except UserNotFoundError:
        pass

    # Remove shadow entry
    try:
        sdb.remove(username)
    except ShadowNotFoundError:
        pass

    # Clear faillock file
    FailLock(username).reset()

    print(f'userdel: user {username!r} removed.')
    sys.exit(0)


if __name__ == '__main__':
    main()
