"""
groupmod: Modify a group.

Usage: groupmod [-g GID] [-n newname] groupname
"""
from __future__ import annotations

import argparse
import sys

from login_tools.db.group import GroupDb, GroupNotFoundError
from login_tools.db.passwd import PasswdDb
from login_tools.privilege import require_root


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='groupmod', description='Modify a group.')
    parser.add_argument('groupname')
    parser.add_argument('-g', '--gid', type=int, default=None, help='New GID')
    parser.add_argument('-n', '--new-name', default=None, help='New group name')
    args = parser.parse_args()

    groupname = args.groupname
    gdb = GroupDb()
    pdb = PasswdDb()

    g_entry = gdb.get_by_name(groupname)
    if g_entry is None:
        print(f'groupmod: group {groupname!r} not found.', file=sys.stderr)
        sys.exit(3)

    if args.gid is not None:
        existing = gdb.get_by_gid(args.gid)
        if existing is not None and existing.groupname != groupname:
            print(f'groupmod: GID {args.gid} is already in use.', file=sys.stderr)
            sys.exit(4)
        old_gid = g_entry.gid
        g_entry.gid = args.gid
        # Update primary GID in /etc/passwd for affected users
        all_users = pdb.all_entries()
        for p in all_users:
            if p.gid == old_gid:
                p.gid = args.gid
                pdb.update(p)

    if args.new_name is not None:
        try:
            GroupDb.validate_groupname(args.new_name)
        except ValueError as exc:
            print(f'groupmod: {exc}', file=sys.stderr)
            sys.exit(2)
        if gdb.get_by_name(args.new_name) is not None:
            print(f'groupmod: group {args.new_name!r} already exists.', file=sys.stderr)
            sys.exit(9)
        old_name = g_entry.groupname
        g_entry.groupname = args.new_name
        from login_tools.atomic import db_lock
        with db_lock(gdb._path):
            entries = gdb.load()
            gdb.save([g_entry if e.groupname == old_name else e for e in entries])
        print(f'groupmod: group {groupname!r} renamed to {args.new_name!r}.')
        sys.exit(0)

    gdb.update(g_entry)
    print(f'groupmod: group {groupname!r} modified.')
    sys.exit(0)


if __name__ == '__main__':
    main()
