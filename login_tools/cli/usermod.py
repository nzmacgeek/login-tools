"""
usermod: Modify a user account.

Usage: usermod [options] username
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import date
from pathlib import Path

from login_tools.db.group import GroupDb
from login_tools.db.passwd import PasswdDb, UserNotFoundError
from login_tools.db.shadow import ShadowDb, ShadowNotFoundError
from login_tools.faillock import FailLock
from login_tools.privilege import require_root
from login_tools import paths


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='usermod', description='Modify a user account.')
    parser.add_argument('username')
    parser.add_argument('-u', '--uid', type=int, default=None)
    parser.add_argument('-g', '--gid', default=None, help='New primary GID or group name')
    parser.add_argument('-G', '--groups', default=None, help='Set supplementary groups (comma-sep)')
    parser.add_argument('-a', '--append', action='store_true', help='Append to -G instead of replacing')
    parser.add_argument('-d', '--home-dir', default=None)
    parser.add_argument('-m', '--move-home', action='store_true',
                        help='Move home directory contents (requires -d)')
    parser.add_argument('-s', '--shell', default=None)
    parser.add_argument('-c', '--comment', default=None)
    parser.add_argument('-l', '--login', default=None, help='New login name')
    parser.add_argument('-L', '--lock', action='store_true')
    parser.add_argument('-U', '--unlock', action='store_true')
    parser.add_argument('-e', '--expiredate', default=None, help='Expiry date YYYY-MM-DD or empty to clear')
    parser.add_argument('-f', '--inactive', type=int, default=None)
    args = parser.parse_args()

    if args.lock and args.unlock:
        print('usermod: -L and -U are mutually exclusive.', file=sys.stderr)
        sys.exit(2)

    username = args.username
    pdb = PasswdDb()
    sdb = ShadowDb()
    gdb = GroupDb()

    p_entry = pdb.get_by_name(username)
    if p_entry is None:
        print(f'usermod: user {username!r} not found.', file=sys.stderr)
        sys.exit(3)

    s_entry = sdb.get(username)

    # Apply changes to passwd entry
    if args.uid is not None:
        if pdb.get_by_uid(args.uid) is not None and pdb.get_by_uid(args.uid).username != username:
            print(f'usermod: UID {args.uid} is already in use.', file=sys.stderr)
            sys.exit(4)
        p_entry.uid = args.uid

    if args.gid is not None:
        try:
            gid = int(args.gid)
            if gdb.get_by_gid(gid) is None:
                print(f'usermod: group with GID {gid} not found.', file=sys.stderr)
                sys.exit(6)
        except ValueError:
            g = gdb.get_by_name(args.gid)
            if g is None:
                print(f'usermod: group {args.gid!r} not found.', file=sys.stderr)
                sys.exit(6)
            gid = g.gid
        p_entry.gid = gid

    if args.home_dir is not None:
        old_home = Path(p_entry.home)
        new_home = Path(args.home_dir)
        if args.move_home and old_home.exists() and old_home != new_home:
            try:
                shutil.move(str(old_home), str(new_home))
                os.chown(new_home, p_entry.uid, p_entry.gid)
            except OSError as exc:
                print(f'usermod: warning: home move failed: {exc}', file=sys.stderr)
        p_entry.home = args.home_dir

    if args.shell is not None:
        p_entry.shell = args.shell

    if args.comment is not None:
        p_entry.comment = args.comment  # type: ignore[attr-defined]
        p_entry.gecos = args.comment

    if args.login is not None:
        new_login = args.login
        try:
            PasswdDb.validate_username(new_login)
        except ValueError as exc:
            print(f'usermod: {exc}', file=sys.stderr)
            sys.exit(2)
        if pdb.get_by_name(new_login) is not None:
            print(f'usermod: user {new_login!r} already exists.', file=sys.stderr)
            sys.exit(3)
        # Rename faillock file
        old_fl = FailLock(username)
        old_path = old_fl._path
        if old_path.exists():
            old_path.rename(old_path.parent / new_login)
        p_entry.username = new_login
        if s_entry is not None:
            s_entry.username = new_login
        username = new_login

    pdb.update(p_entry)

    # Apply changes to shadow entry
    if s_entry is not None:
        if args.expiredate is not None:
            if args.expiredate.strip():
                try:
                    d = date.fromisoformat(args.expiredate)
                    s_entry.expire_date = (d - date(1970, 1, 1)).days
                except ValueError:
                    print(f'usermod: invalid date {args.expiredate!r}', file=sys.stderr)
                    sys.exit(2)
            else:
                s_entry.expire_date = None

        if args.inactive is not None:
            s_entry.inactive_days = args.inactive if args.inactive >= 0 else None

        sdb.update(s_entry)

    if args.lock:
        try:
            sdb.lock(p_entry.username)
        except ShadowNotFoundError:
            pass

    if args.unlock:
        try:
            sdb.unlock(p_entry.username)
        except ShadowNotFoundError:
            pass

    # Supplementary groups
    if args.groups is not None:
        new_groups = [g.strip() for g in args.groups.split(',') if g.strip()]
        if args.append:
            for gname in new_groups:
                if gdb.get_by_name(gname) is None:
                    print(f'usermod: group {gname!r} not found.', file=sys.stderr)
                    sys.exit(6)
                gdb.add_member(gname, p_entry.username)
        else:
            # Remove from all current supplementary groups then add to new
            gdb.remove_user_from_all_groups(p_entry.username)
            for gname in new_groups:
                if gdb.get_by_name(gname) is None:
                    print(f'usermod: group {gname!r} not found.', file=sys.stderr)
                    sys.exit(6)
                gdb.add_member(gname, p_entry.username)

    print(f'usermod: user {args.username!r} modified.')
    sys.exit(0)


if __name__ == '__main__':
    main()
