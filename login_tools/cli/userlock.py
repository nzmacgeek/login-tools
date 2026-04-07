"""
userlock: Lock/unlock a user account and manage faillock state.

Usage: userlock {--lock | --unlock | --status | --reset-faillock} username
"""
from __future__ import annotations

import argparse
import sys

from login_tools.db.passwd import PasswdDb
from login_tools.db.shadow import ShadowDb, ShadowNotFoundError
from login_tools.faillock import FailLock
from login_tools.policy import load_policy
from login_tools.privilege import require_root


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(
        prog='userlock',
        description='Lock/unlock a user account or manage failed login state.',
    )
    parser.add_argument('username')
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--lock', action='store_true', help='Shadow-lock the account')
    action_group.add_argument('--unlock', action='store_true', help='Shadow-unlock the account')
    action_group.add_argument('--status', action='store_true',
                              help='Print account lock status and faillock count')
    action_group.add_argument('--reset-faillock', action='store_true',
                              help='Clear failed login attempts for this user')
    args = parser.parse_args()

    username = args.username
    pdb = PasswdDb()
    sdb = ShadowDb()

    if pdb.get_by_name(username) is None:
        print(f'userlock: user {username!r} not found.', file=sys.stderr)
        sys.exit(3)

    _, lo_policy = load_policy()
    fl = FailLock(username)

    if args.reset_faillock:
        fl.reset()
        print(f'userlock: faillock for {username!r} cleared.')
        sys.exit(0)

    shadow_entry = sdb.get(username)

    if args.status:
        if shadow_entry is None:
            lock_status = 'NO_SHADOW'
        elif shadow_entry.is_locked():
            lock_status = 'LOCKED'
        elif shadow_entry.has_no_password():
            lock_status = 'NO_PASSWORD'
        else:
            lock_status = 'UNLOCKED'
        fail_count = fl.failure_count(lo_policy)
        locked_out = fl.is_locked_out(lo_policy)
        print(
            f'{username} {lock_status} FAILLOCK:{fail_count} '
            f'{"LOCKED_OUT" if locked_out else "OK"}'
        )
        sys.exit(1 if shadow_entry and shadow_entry.is_locked() else 0)

    if args.lock:
        if shadow_entry is None:
            print(f'userlock: no shadow entry for {username!r}.', file=sys.stderr)
            sys.exit(3)
        try:
            sdb.lock(username)
            print(f'userlock: account {username!r} locked.')
        except ShadowNotFoundError:
            print(f'userlock: no shadow entry for {username!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    if args.unlock:
        if shadow_entry is None:
            print(f'userlock: no shadow entry for {username!r}.', file=sys.stderr)
            sys.exit(3)
        try:
            sdb.unlock(username)
            print(f'userlock: account {username!r} unlocked.')
        except ShadowNotFoundError:
            print(f'userlock: no shadow entry for {username!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)


if __name__ == '__main__':
    main()
