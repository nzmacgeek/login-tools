"""
chgrp: Change file group ownership.

Usage: chgrp [-R] [-v] [-c] GROUP FILE...
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from login_tools.db.group import GroupDb
from login_tools.privilege import require_root


def _resolve_group(group_str: str) -> int:
    """
    Resolve a group name or numeric GID string to an integer GID.
    Raises ValueError for unknown group names.
    """
    try:
        return int(group_str)
    except ValueError:
        pass
    gdb = GroupDb()
    entry = gdb.get_by_name(group_str)
    if entry is None:
        raise ValueError(f'invalid group: {group_str!r}')
    return entry.gid


def _chgrp_path(path: Path, gid: int, verbose: bool, changes: bool) -> int:
    """Apply chgrp to a single path. Returns 0 on success, 1 on error."""
    try:
        st = path.stat()
        old_gid = st.st_gid
        os.chown(path, -1, gid)
        if verbose or (changes and old_gid != gid):
            if old_gid != gid:
                print(f"changed group of '{path}' from {old_gid} to {gid}")
            elif verbose:
                print(f"group of '{path}' retained as {old_gid}")
        return 0
    except OSError as exc:
        print(f'chgrp: {path}: {exc}', file=sys.stderr)
        return 1


def _chgrp_recursive(path: Path, gid: int, verbose: bool, changes: bool) -> int:
    rc = _chgrp_path(path, gid, verbose, changes)
    if path.is_dir():
        for child in path.iterdir():
            rc |= _chgrp_recursive(child, gid, verbose, changes)
    return rc


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(
        prog='chgrp',
        description='Change file group ownership.',
    )
    parser.add_argument('group', metavar='GROUP', help='New group name or GID')
    parser.add_argument('files', nargs='+', metavar='FILE', help='Files to modify')
    parser.add_argument(
        '-R', '--recursive',
        action='store_true',
        help='Operate on files and directories recursively',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Output a diagnostic for every file processed',
    )
    parser.add_argument(
        '-c', '--changes',
        action='store_true',
        help='Like --verbose but report only when a change is made',
    )
    args = parser.parse_args()

    try:
        gid = _resolve_group(args.group)
    except ValueError as exc:
        print(f'chgrp: {exc}', file=sys.stderr)
        sys.exit(1)

    rc = 0
    for f in args.files:
        p = Path(f)
        if not p.exists() and not p.is_symlink():
            print(
                f"chgrp: cannot access '{f}': No such file or directory",
                file=sys.stderr,
            )
            rc = 1
            continue
        if args.recursive:
            rc |= _chgrp_recursive(p, gid, args.verbose, args.changes)
        else:
            rc |= _chgrp_path(p, gid, args.verbose, args.changes)
    sys.exit(rc)


if __name__ == '__main__':
    main()
