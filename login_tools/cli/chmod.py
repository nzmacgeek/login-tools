"""
chmod: Change file mode bits.

Usage: chmod [-R] [-v] [-c] MODE FILE...
"""
from __future__ import annotations

import argparse
import stat
import sys
from pathlib import Path


def _apply_clause(current: int, clause: str) -> int:
    """Apply one symbolic mode clause (e.g. u+x, go-w, a=r) to current mode bits."""
    i = 0
    who_chars = ''
    while i < len(clause) and clause[i] in 'ugoa':
        who_chars += clause[i]
        i += 1

    if i >= len(clause) or clause[i] not in '+-=':
        raise ValueError(f'invalid mode clause: {clause!r}')

    op = clause[i]
    perm_chars = clause[i + 1:]

    # Determine the 'who' mask (which permission slots to affect)
    who_bits = 0
    if not who_chars or 'a' in who_chars:
        who_bits = 0o777
    if 'u' in who_chars:
        who_bits |= 0o700
    if 'g' in who_chars:
        who_bits |= 0o070
    if 'o' in who_chars:
        who_bits |= 0o007

    # Determine permission bits to apply (always spread across all three slots)
    perm_bits = 0
    for c in perm_chars:
        if c == 'r':
            perm_bits |= 0o444
        elif c == 'w':
            perm_bits |= 0o222
        elif c == 'x':
            perm_bits |= 0o111
        elif c == 'X':
            # Set execute only if the path is a directory or already has any execute bit
            if stat.S_ISDIR(current) or (current & 0o111):
                perm_bits |= 0o111
        elif c == 's':
            perm_bits |= (stat.S_ISUID | stat.S_ISGID)
        elif c == 't':
            perm_bits |= stat.S_ISVTX
        elif c == 'u':
            user_bits = (current & 0o700) >> 6
            perm_bits |= user_bits * 0o111
        elif c == 'g':
            grp_bits = (current & 0o070) >> 3
            perm_bits |= grp_bits * 0o111
        elif c == 'o':
            oth_bits = current & 0o007
            perm_bits |= oth_bits * 0o111
        else:
            raise ValueError(f'invalid permission character: {c!r}')

    # Special bits (SUID, SGID, SVTX) are outside the 0o777 'who' mask and
    # must be handled separately so they are not accidentally cleared.
    # Mapping: u → SUID, g → SGID, o/a → SVTX (traditional convention)
    if not who_chars or 'a' in who_chars:
        special_who = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    else:
        special_who = 0
        if 'u' in who_chars:
            special_who |= stat.S_ISUID
        if 'g' in who_chars:
            special_who |= stat.S_ISGID
        if 'o' in who_chars:
            special_who |= stat.S_ISVTX
    special_masked = perm_bits & special_who

    masked = perm_bits & who_bits

    if op == '+':
        return current | masked | special_masked
    elif op == '-':
        return current & ~(masked | special_masked)
    else:  # '='
        return (current & ~(who_bits | special_who)) | masked | special_masked


def _apply_symbolic_mode(current: int, spec: str) -> int:
    """Apply a comma-separated symbolic mode string to current mode bits."""
    for clause in spec.split(','):
        current = _apply_clause(current, clause)
    return current


def _parse_mode(mode_str: str, current: int) -> int:
    """
    Parse a mode string (octal or symbolic) and return the resulting mode.
    For octal modes the current mode is ignored; for symbolic it is needed.
    """
    try:
        return int(mode_str, 8)
    except ValueError:
        pass
    return _apply_symbolic_mode(current, mode_str)


def _chmod_path(path: Path, mode_str: str, verbose: bool, changes: bool) -> int:
    """Apply chmod to a single path. Returns 0 on success, 1 on error."""
    try:
        st = path.stat()
        old_mode = st.st_mode & 0o7777
        new_mode = _parse_mode(mode_str, st.st_mode)
        path.chmod(new_mode)
        if verbose or (changes and old_mode != new_mode):
            if old_mode != new_mode:
                print(f"mode of '{path}' changed from {old_mode:04o} to {new_mode:04o}")
            elif verbose:
                print(f"mode of '{path}' retained as {old_mode:04o}")
        return 0
    except (OSError, ValueError) as exc:
        print(f'chmod: {path}: {exc}', file=sys.stderr)
        return 1


def _chmod_recursive(path: Path, mode_str: str, verbose: bool, changes: bool) -> int:
    rc = _chmod_path(path, mode_str, verbose, changes)
    if not path.is_symlink() and path.is_dir():
        for child in path.iterdir():
            rc |= _chmod_recursive(child, mode_str, verbose, changes)
    return rc


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='chmod',
        description='Change file mode bits.',
    )
    parser.add_argument(
        'mode',
        help='File mode: octal (e.g. 755) or symbolic (e.g. u+x, a=rw)',
    )
    parser.add_argument('files', nargs='+', metavar='FILE', help='Files to modify')
    parser.add_argument(
        '-R', '--recursive',
        action='store_true',
        help='Change files and directories recursively',
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

    rc = 0
    for f in args.files:
        p = Path(f)
        if not p.exists() and not p.is_symlink():
            print(
                f"chmod: cannot access '{f}': No such file or directory",
                file=sys.stderr,
            )
            rc = 1
            continue
        if args.recursive:
            rc |= _chmod_recursive(p, args.mode, args.verbose, args.changes)
        else:
            rc |= _chmod_path(p, args.mode, args.verbose, args.changes)
    sys.exit(rc)


if __name__ == '__main__':
    main()
