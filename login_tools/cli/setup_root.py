"""
setup-root: Securely set the root password for the first time.

Only succeeds if root has no password set (hash is '!', '!!', '*', or '').
If root already has a real password (including locked), refuses with exit 1.
"""
from __future__ import annotations

import getpass
import sys

from login_tools._compat_crypt import hash_password
from login_tools.db.shadow import ShadowDb, ShadowEntry, days_since_epoch
from login_tools.policy import check_password_complexity, load_policy


def main() -> None:
    sdb = ShadowDb()
    entry = sdb.get('root')

    if entry is None:
        # No shadow entry for root — treat as 'no password set'
        entry = ShadowEntry.new_blank('root')
        create_entry = True
    else:
        create_entry = False

    if not entry.has_no_password():
        print(
            'setup-root: root already has a password set. '
            'Use `passwd root` (as root) to change it.',
            file=sys.stderr,
        )
        sys.exit(1)

    pw_policy, _ = load_policy()

    try:
        pw1 = getpass.getpass('New root password: ')
        pw2 = getpass.getpass('Retype new root password: ')
    except (EOFError, KeyboardInterrupt):
        print('\nAborted.', file=sys.stderr)
        sys.exit(4)

    if pw1 != pw2:
        print('setup-root: passwords do not match.', file=sys.stderr)
        sys.exit(2)

    violations = check_password_complexity(pw1, pw_policy, username='root')
    if violations:
        print('setup-root: password does not meet complexity requirements:', file=sys.stderr)
        for v in violations:
            print(f'  - {v}', file=sys.stderr)
        sys.exit(3)

    hashed = hash_password(pw1)

    if create_entry:
        entry.hashed_password = hashed
        entry.last_changed = days_since_epoch()
        sdb.add(entry)
    else:
        sdb.set_password('root', hashed)

    print('Root password set successfully.')
    sys.exit(0)


if __name__ == '__main__':
    main()
