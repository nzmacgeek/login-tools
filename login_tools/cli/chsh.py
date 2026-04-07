"""
chsh: Change a user's login shell.

Usage: chsh [-s shell] [-l] [username]
"""
from __future__ import annotations

import argparse
import sys

from login_tools.db.passwd import PasswdDb, UserNotFoundError
from login_tools.privilege import get_current_username, is_root
from login_tools import paths


def _valid_shells() -> list[str]:
    """Read /etc/shells and return a list of allowed shell paths."""
    try:
        text = paths.shells_path().read_text()
        return [line.strip() for line in text.splitlines()
                if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        return []


def main() -> None:
    parser = argparse.ArgumentParser(prog='chsh', description='Change login shell.')
    parser.add_argument('username', nargs='?', help='User to modify (default: current user)')
    parser.add_argument('-s', '--shell', default=None, help='New shell path')
    parser.add_argument('-l', '--list-shells', action='store_true', help='List available shells')
    args = parser.parse_args()

    if args.list_shells:
        shells = _valid_shells()
        if shells:
            print('\n'.join(shells))
        else:
            print('(no shells listed in /etc/shells)')
        sys.exit(0)

    root = is_root()
    current_user = get_current_username()
    target = args.username or current_user

    if not root and target != current_user:
        print(f'chsh: permission denied to change {target!r}\'s shell.', file=sys.stderr)
        sys.exit(1)

    pdb = PasswdDb()
    entry = pdb.get_by_name(target)
    if entry is None:
        print(f'chsh: user {target!r} not found.', file=sys.stderr)
        sys.exit(3)

    if args.shell is None:
        # Interactive prompt
        print(f'Changing shell for {target}.')
        print(f'Current shell: {entry.shell}')
        try:
            new_shell = input('New shell [press Enter to keep current]: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nAborted.', file=sys.stderr)
            sys.exit(1)
        if not new_shell:
            print('Shell unchanged.')
            sys.exit(0)
    else:
        new_shell = args.shell

    if not new_shell.startswith('/'):
        print(f'chsh: shell {new_shell!r} must be an absolute path.', file=sys.stderr)
        sys.exit(2)

    # Non-root users: shell must be in /etc/shells
    if not root:
        valid = _valid_shells()
        if valid and new_shell not in valid:
            print(
                f'chsh: {new_shell!r} is not listed in /etc/shells.',
                file=sys.stderr,
            )
            sys.exit(4)

    entry.shell = new_shell
    try:
        pdb.update(entry)
    except UserNotFoundError:
        print(f'chsh: user {target!r} not found.', file=sys.stderr)
        sys.exit(3)

    print(f'chsh: shell changed to {new_shell!r} for {target}.')
    sys.exit(0)


if __name__ == '__main__':
    main()
