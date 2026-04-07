"""
passwd: Change user passwords, lock/unlock accounts, and show password status.

Usage: passwd [-l|-u|-d|-e|-S] [username]

Without a username: changes the calling user's password.
As root: can change any user's password without knowing the current one.
Non-root users targeting themselves must provide their current password.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from login_tools._compat_crypt import hash_password, verify_password
from login_tools.db.passwd import PasswdDb, UserNotFoundError
from login_tools.db.shadow import ShadowDb, ShadowEntry, ShadowNotFoundError, days_since_epoch
from login_tools.policy import (
    check_password_complexity,
    check_password_history,
    load_policy,
    record_password_history,
)
from login_tools.privilege import get_current_username, is_root


def _status_str(entry: ShadowEntry) -> str:
    if entry.is_locked():
        status = 'L'
    elif entry.has_no_password():
        status = 'NP'
    else:
        status = 'P'
    lc = entry.last_changed if entry.last_changed is not None else 0
    min_a = entry.min_age if entry.min_age is not None else 0
    max_a = entry.max_age if entry.max_age is not None else 99999
    warn = entry.warn_days if entry.warn_days is not None else 7
    inact = entry.inactive_days if entry.inactive_days is not None else -1
    return f'{entry.username} {status} {lc} {min_a} {max_a} {warn} {inact}'


def _do_change_password(username: str, as_root: bool) -> int:
    """Returns exit code."""
    pdb = PasswdDb()
    sdb = ShadowDb()
    pw_policy, _ = load_policy()

    if pdb.get_by_name(username) is None:
        print(f'passwd: user {username!r} not found.', file=sys.stderr)
        return 3

    shadow_entry = sdb.get(username)
    if shadow_entry is None:
        print(f'passwd: no shadow entry for {username!r}.', file=sys.stderr)
        return 3

    try:
        if not as_root:
            current = getpass.getpass('Current password: ')
            if not verify_password(current, shadow_entry.hashed_password):
                print('passwd: authentication failure.', file=sys.stderr)
                return 5

        pw1 = getpass.getpass('New password: ')
        pw2 = getpass.getpass('Retype new password: ')
    except (EOFError, KeyboardInterrupt):
        print('\nAborted.', file=sys.stderr)
        return 1

    if pw1 != pw2:
        print('passwd: passwords do not match.', file=sys.stderr)
        return 6

    violations = check_password_complexity(pw1, pw_policy, username=username)
    if violations:
        print('passwd: password does not meet complexity requirements:', file=sys.stderr)
        for v in violations:
            print(f'  - {v}', file=sys.stderr)
        return 4

    if check_password_history(username, pw1, pw_policy):
        print('passwd: password previously used; choose a different password.', file=sys.stderr)
        return 4

    passwd_entry = pdb.get_by_name(username)
    old_hash = shadow_entry.hashed_password
    new_hash = hash_password(pw1)

    record_password_history(username, passwd_entry.uid, old_hash, pw_policy)
    sdb.set_password(username, new_hash)

    print(f'passwd: password updated successfully for {username}.')
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='passwd',
        description='Change user password or account status.',
        add_help=True,
    )
    parser.add_argument('username', nargs='?', help='User to modify (default: current user)')
    mutex = parser.add_mutually_exclusive_group()
    mutex.add_argument('-l', '--lock', action='store_true', help='Lock the account')
    mutex.add_argument('-u', '--unlock', action='store_true', help='Unlock the account')
    mutex.add_argument('-d', '--delete', action='store_true', help='Delete the password (set to !!)')
    mutex.add_argument('-e', '--expire', action='store_true', help='Force password expiry at next login')
    mutex.add_argument('-S', '--status', action='store_true', help='Print account status')
    args = parser.parse_args()

    current_user = get_current_username()
    root = is_root()

    # Determine target username
    target = args.username or current_user

    # Non-root users may only operate on themselves (for non-status operations)
    if not root and target != current_user:
        print(f'passwd: permission denied to modify {target!r}.', file=sys.stderr)
        sys.exit(1)

    pdb = PasswdDb()
    sdb = ShadowDb()

    if pdb.get_by_name(target) is None:
        print(f'passwd: user {target!r} not found.', file=sys.stderr)
        sys.exit(3)

    if args.status:
        entry = sdb.get(target)
        if entry is None:
            print(f'passwd: no shadow entry for {target!r}.', file=sys.stderr)
            sys.exit(3)
        print(_status_str(entry))
        sys.exit(0)

    if args.lock:
        if not root and target != current_user:
            print('passwd: permission denied.', file=sys.stderr)
            sys.exit(1)
        try:
            sdb.lock(target)
            print(f'passwd: account {target!r} locked.')
        except ShadowNotFoundError:
            print(f'passwd: no shadow entry for {target!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    if args.unlock:
        if not root:
            print('passwd: only root can unlock accounts.', file=sys.stderr)
            sys.exit(1)
        try:
            sdb.unlock(target)
            print(f'passwd: account {target!r} unlocked.')
        except ShadowNotFoundError:
            print(f'passwd: no shadow entry for {target!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    if args.delete:
        if not root:
            print('passwd: only root can delete passwords.', file=sys.stderr)
            sys.exit(1)
        try:
            sdb.set_password(target, '!!')
            print(f'passwd: password for {target!r} deleted.')
        except ShadowNotFoundError:
            print(f'passwd: no shadow entry for {target!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    if args.expire:
        if not root:
            print('passwd: only root can force password expiry.', file=sys.stderr)
            sys.exit(1)
        try:
            entry = sdb.get(target)
            if entry is None:
                raise ShadowNotFoundError(target)
            entry.last_changed = 0
            sdb.update(entry)
            print(f'passwd: password for {target!r} expired.')
        except ShadowNotFoundError:
            print(f'passwd: no shadow entry for {target!r}.', file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    # Default: change password
    code = _do_change_password(target, as_root=(root and target != current_user))
    sys.exit(code)


if __name__ == '__main__':
    main()
