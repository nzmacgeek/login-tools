"""
useradd: Create a new user account.

Usage: useradd [options] username
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import date
from pathlib import Path

from login_tools._compat_crypt import hash_password
from login_tools.db.group import GroupDb, GroupEntry
from login_tools.db.passwd import PasswdDb, PasswdEntry, UserExistsError, UIDInUseError
from login_tools.db.shadow import ShadowDb, ShadowEntry, days_since_epoch
from login_tools.privilege import require_root
from login_tools import paths


def _date_to_epoch_days(date_str: str) -> int:
    """Parse YYYY-MM-DD and return days since 1970-01-01."""
    try:
        d = date.fromisoformat(date_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f'Invalid date {date_str!r}, expected YYYY-MM-DD')
    return (d - date(1970, 1, 1)).days


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='useradd', description='Create a new user.')
    parser.add_argument('username')
    parser.add_argument('-u', '--uid', type=int, default=None, help='Explicit UID')
    parser.add_argument('-g', '--gid', default=None, help='Primary group GID or name')
    parser.add_argument('-G', '--groups', default=None, help='Supplementary groups (comma-separated)')
    parser.add_argument('-d', '--home-dir', default=None, help='Home directory')
    parser.add_argument('-s', '--shell', default='/bin/sh', help='Login shell')
    parser.add_argument('-c', '--comment', default='', help='GECOS comment field')
    parser.add_argument('-m', '--create-home', action='store_true', help='Create home directory')
    parser.add_argument('-M', '--no-create-home', action='store_true', help='Do not create home directory')
    parser.add_argument('-r', '--system', action='store_true', help='Create a system account')
    parser.add_argument('-p', '--password', default=None, help='Pre-hashed password (for scripting)')
    parser.add_argument('-e', '--expiredate', default=None, help='Account expiry date (YYYY-MM-DD)')
    parser.add_argument('-f', '--inactive', type=int, default=None, help='Password inactive days after expiry')
    args = parser.parse_args()

    username = args.username
    try:
        PasswdDb.validate_username(username)
    except ValueError as exc:
        print(f'useradd: {exc}', file=sys.stderr)
        sys.exit(2)

    pdb = PasswdDb()
    sdb = ShadowDb()
    gdb = GroupDb()

    if pdb.get_by_name(username) is not None:
        print(f'useradd: user {username!r} already exists.', file=sys.stderr)
        sys.exit(3)

    # Resolve UID
    if args.uid is not None:
        uid = args.uid
        if pdb.get_by_uid(uid) is not None:
            print(f'useradd: UID {uid} is already in use.', file=sys.stderr)
            sys.exit(4)
    else:
        try:
            uid = pdb.next_uid(system=args.system)
        except RuntimeError as exc:
            print(f'useradd: {exc}', file=sys.stderr)
            sys.exit(4)

    # Resolve primary GID
    if args.gid is not None:
        # Try numeric first
        try:
            gid = int(args.gid)
            g = gdb.get_by_gid(gid)
            if g is None:
                print(f'useradd: group with GID {gid} not found.', file=sys.stderr)
                sys.exit(9)
        except ValueError:
            # Treat as name
            g = gdb.get_by_name(args.gid)
            if g is None:
                print(f'useradd: group {args.gid!r} not found.', file=sys.stderr)
                sys.exit(9)
            gid = g.gid
    else:
        # Create a group matching the username
        try:
            gid = uid if gdb.get_by_gid(uid) is None else gdb.next_gid(system=args.system)
            new_group = GroupEntry(groupname=username, password='x', gid=gid, members=[])
            gdb.add(new_group)
        except Exception as exc:
            print(f'useradd: could not create primary group: {exc}', file=sys.stderr)
            sys.exit(9)

    # Home directory
    home = args.home_dir or (
        '/' if args.system else str(paths.home_base() / username)
    )

    # Expiry
    expire_date: int | None = None
    if args.expiredate:
        try:
            expire_date = _date_to_epoch_days(args.expiredate)
        except argparse.ArgumentTypeError as exc:
            print(f'useradd: {exc}', file=sys.stderr)
            sys.exit(2)

    # Create passwd entry
    passwd_entry = PasswdEntry(
        username=username,
        password='x',
        uid=uid,
        gid=gid,
        gecos=args.comment,
        home=home,
        shell=args.shell,
    )
    try:
        pdb.add(passwd_entry)
    except UserExistsError:
        print(f'useradd: user {username!r} already exists.', file=sys.stderr)
        sys.exit(3)
    except UIDInUseError:
        print(f'useradd: UID {uid} is already in use.', file=sys.stderr)
        sys.exit(4)

    # Create shadow entry
    hashed_pw = args.password if args.password else '!!'
    shadow_entry = ShadowEntry(
        username=username,
        hashed_password=hashed_pw,
        last_changed=days_since_epoch(),
        min_age=0,
        max_age=99999,
        warn_days=7,
        inactive_days=args.inactive,
        expire_date=expire_date,
        reserved='',
    )
    sdb.add(shadow_entry)

    # Supplementary groups
    if args.groups:
        for gname in args.groups.split(','):
            gname = gname.strip()
            if not gname:
                continue
            g = gdb.get_by_name(gname)
            if g is None:
                print(f'useradd: supplementary group {gname!r} not found.', file=sys.stderr)
                # Don't abort — partial creation is cleaned up below would be complex
                sys.exit(9)
            gdb.add_member(gname, username)

    # Create home directory
    if args.create_home and not args.no_create_home and not args.system:
        home_path = Path(home)
        try:
            home_path.mkdir(parents=True, exist_ok=True)
            os.chown(home_path, uid, gid)
            home_path.chmod(0o755)
        except OSError as exc:
            print(f'useradd: warning: could not create home directory: {exc}', file=sys.stderr)

    print(f'useradd: user {username!r} created with UID {uid}.')
    sys.exit(0)


if __name__ == '__main__':
    main()
