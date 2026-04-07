"""
groupadd: Create a new group.

Usage: groupadd [-g GID] [-r] groupname
"""
from __future__ import annotations

import argparse
import sys

from login_tools.db.group import GroupDb, GroupEntry, GroupExistsError, GIDInUseError
from login_tools.privilege import require_root


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='groupadd', description='Create a new group.')
    parser.add_argument('groupname')
    parser.add_argument('-g', '--gid', type=int, default=None, help='Explicit GID')
    parser.add_argument('-r', '--system', action='store_true', help='Create a system group')
    args = parser.parse_args()

    groupname = args.groupname
    try:
        GroupDb.validate_groupname(groupname)
    except ValueError as exc:
        print(f'groupadd: {exc}', file=sys.stderr)
        sys.exit(2)

    gdb = GroupDb()

    if gdb.get_by_name(groupname) is not None:
        print(f'groupadd: group {groupname!r} already exists.', file=sys.stderr)
        sys.exit(3)

    if args.gid is not None:
        gid = args.gid
        if gdb.get_by_gid(gid) is not None:
            print(f'groupadd: GID {gid} is already in use.', file=sys.stderr)
            sys.exit(4)
    else:
        try:
            gid = gdb.next_gid(system=args.system)
        except RuntimeError as exc:
            print(f'groupadd: {exc}', file=sys.stderr)
            sys.exit(4)

    entry = GroupEntry(groupname=groupname, password='x', gid=gid, members=[])
    try:
        gdb.add(entry)
    except GroupExistsError:
        print(f'groupadd: group {groupname!r} already exists.', file=sys.stderr)
        sys.exit(3)
    except GIDInUseError:
        print(f'groupadd: GID {gid} is already in use.', file=sys.stderr)
        sys.exit(4)

    print(f'groupadd: group {groupname!r} created with GID {gid}.')
    sys.exit(0)


if __name__ == '__main__':
    main()
