"""
groupdel: Delete a group.

Usage: groupdel groupname
"""
from __future__ import annotations

import argparse
import sys

from login_tools.db.group import GroupDb, GroupNotFoundError
from login_tools.db.passwd import PasswdDb
from login_tools.privilege import require_root


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(prog='groupdel', description='Delete a group.')
    parser.add_argument('groupname')
    args = parser.parse_args()

    groupname = args.groupname
    gdb = GroupDb()
    pdb = PasswdDb()

    g_entry = gdb.get_by_name(groupname)
    if g_entry is None:
        print(f'groupdel: group {groupname!r} not found.', file=sys.stderr)
        sys.exit(3)

    # Refuse if it is the primary group of any user
    if gdb.is_primary_group_of_any_user(g_entry.gid, pdb):
        print(
            f'groupdel: cannot remove group {groupname!r}: '
            f'it is the primary group of one or more users.',
            file=sys.stderr,
        )
        sys.exit(8)

    try:
        gdb.remove(groupname)
    except GroupNotFoundError:
        print(f'groupdel: group {groupname!r} not found.', file=sys.stderr)
        sys.exit(3)

    print(f'groupdel: group {groupname!r} removed.')
    sys.exit(0)


if __name__ == '__main__':
    main()
