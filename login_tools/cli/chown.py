"""
chown: Change file owner and group.

Usage: chown [-R] [-v] [-c] OWNER[:GROUP] FILE...
       chown [-R] [-v] [-c] :GROUP FILE...
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from login_tools.db.group import GroupDb
from login_tools.db.passwd import PasswdDb
from login_tools.privilege import require_root


def _resolve_owner(spec: str) -> tuple[int, int]:
    """
    Parse an OWNER[:GROUP] or :GROUP specification.

    Returns (uid, gid) where -1 means 'do not change'.
    Raises ValueError for unknown users or groups.
    """
    if ':' in spec:
        owner_str, group_str = spec.split(':', 1)
        if not owner_str and not group_str:
            raise ValueError("invalid spec: ':'")
    else:
        owner_str = spec
        group_str = ''

    uid: int = -1
    gid: int = -1

    if owner_str:
        try:
            uid = int(owner_str)
        except ValueError:
            pdb = PasswdDb()
            entry = pdb.get_by_name(owner_str)
            if entry is None:
                raise ValueError(f'invalid user: {owner_str!r}')
            uid = entry.uid
            # When no group is specified, also change to the user's primary group
            if not group_str:
                gid = entry.gid
        else:
            if uid < 0:
                raise ValueError(f'invalid user: {owner_str!r}')

    if group_str:
        try:
            gid = int(group_str)
        except ValueError:
            gdb = GroupDb()
            gentry = gdb.get_by_name(group_str)
            if gentry is None:
                raise ValueError(f'invalid group: {group_str!r}')
            gid = gentry.gid
        else:
            if gid < 0:
                raise ValueError(f'invalid group: {group_str!r}')

    return uid, gid


def _chown_path(path: Path, uid: int, gid: int, verbose: bool, changes: bool) -> int:
    """Apply chown to a single path. Returns 0 on success, 1 on error."""
    try:
        st = path.lstat()
        old_uid = st.st_uid
        old_gid = st.st_gid
        os.lchown(path, uid, gid)
        if verbose or changes:
            new_uid = uid if uid != -1 else old_uid
            new_gid = gid if gid != -1 else old_gid
            if old_uid != new_uid or old_gid != new_gid:
                print(
                    f"changed ownership of '{path}' "
                    f"from {old_uid}:{old_gid} to {new_uid}:{new_gid}"
                )
            elif verbose:
                print(f"ownership of '{path}' retained as {old_uid}:{old_gid}")
        return 0
    except OSError as exc:
        print(f'chown: {path}: {exc}', file=sys.stderr)
        return 1


def _chown_recursive(path: Path, uid: int, gid: int, verbose: bool, changes: bool) -> int:
    rc = _chown_path(path, uid, gid, verbose, changes)
    if path.is_symlink():
        return rc
    if path.is_dir():
        for child in path.iterdir():
            rc |= _chown_recursive(child, uid, gid, verbose, changes)
    return rc


def main() -> None:
    require_root()

    parser = argparse.ArgumentParser(
        prog='chown',
        description='Change file owner and group.',
    )
    parser.add_argument(
        'owner',
        metavar='OWNER[:GROUP]',
        help='New owner, optionally followed by :GROUP',
    )
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
        uid, gid = _resolve_owner(args.owner)
    except ValueError as exc:
        print(f'chown: {exc}', file=sys.stderr)
        sys.exit(1)

    rc = 0
    for f in args.files:
        p = Path(f)
        if not p.exists() and not p.is_symlink():
            print(
                f"chown: cannot access '{f}': No such file or directory",
                file=sys.stderr,
            )
            rc = 1
            continue
        if args.recursive:
            rc |= _chown_recursive(p, uid, gid, args.verbose, args.changes)
        else:
            rc |= _chown_path(p, uid, gid, args.verbose, args.changes)
    sys.exit(rc)


if __name__ == '__main__':
    main()
