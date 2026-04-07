"""
login: Authenticate and start a user session.

Intended to be launched by the BlueyOS getty process (matey).
Does NOT return — on success it exec()s the user's shell.

Flow:
  1. Print /etc/issue if it exists.
  2. Prompt for username if not given.
  3. Validate username exists in passwd (fake-verify if not, to prevent enumeration).
  4. Check shadow: account expired → exit 2.
  5. Check faillock: locked out → print wait time → exit 2.
  6. Prompt for password via getpass (reads /dev/tty).
  7. Verify: wrong → record_failure(), sleep, retry up to 3 times then exit 1.
  8. Success: reset faillock.
  9. Must-change-password: run inline change flow.
 10. drop_privileges(uid, gid), set environment, print motd.
 11. os.chdir(home), os.execvpe(shell, [shell], env).

Exit codes:
  0  Shell exited normally (only if shell exec fails — should not happen)
  1  Authentication failure (too many wrong passwords)
  2  Account locked or expired
  3  System error
"""
from __future__ import annotations

import getpass
import os
import sys
import time

from login_tools._compat_crypt import hash_password, verify_password
from login_tools.db.passwd import PasswdDb
from login_tools.db.shadow import ShadowDb, ShadowEntry, days_since_epoch
from login_tools.faillock import FailLock
from login_tools.policy import check_password_complexity, load_policy, record_password_history
from login_tools.privilege import drop_privileges
from login_tools import paths

MAX_TRIES = 3
DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def _print_file(path_fn) -> None:  # type: ignore[type-arg]
    """Print the contents of a path (from a callable) if it exists."""
    try:
        p = path_fn()
        if p.exists():
            print(p.read_text(), end='')
    except OSError:
        pass


def _fake_verify_sleep() -> None:
    """Sleep approximately as long as a real SHA-512 verify would take,
    to prevent username enumeration via timing."""
    time.sleep(0.2)


def _get_tty_password(prompt: str) -> str:
    """Read a password from /dev/tty (bypasses redirected stdin)."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return ''


def _inline_password_change(username: str, uid: int) -> None:
    """
    Force the user to set a new password before proceeding.
    Loops until a valid password is entered.
    """
    print('You must change your password before logging in.')
    pw_policy, _ = load_policy()
    pdb = PasswdDb()
    sdb = ShadowDb()

    while True:
        try:
            pw1 = _get_tty_password('New password: ')
            pw2 = _get_tty_password('Retype new password: ')
        except (EOFError, KeyboardInterrupt):
            print('\nPassword change cancelled. Login aborted.', file=sys.stderr)
            sys.exit(1)

        if pw1 != pw2:
            print('Passwords do not match. Try again.')
            continue

        violations = check_password_complexity(pw1, pw_policy, username=username)
        if violations:
            print('Password does not meet requirements:')
            for v in violations:
                print(f'  - {v}')
            continue

        entry = sdb.get(username)
        old_hash = entry.hashed_password if entry else '!!'
        new_hash = hash_password(pw1)
        passwd_entry = pdb.get_by_name(username)
        if passwd_entry:
            record_password_history(username, passwd_entry.uid, old_hash, pw_policy)
        sdb.set_password(username, new_hash)
        print('Password changed successfully.')
        return


def main() -> None:
    # Optional username argument (typically set by getty)
    username_arg: str | None = sys.argv[1] if len(sys.argv) > 1 else None

    _print_file(paths.issue_path)

    pdb = PasswdDb()
    sdb = ShadowDb()
    pw_policy, lo_policy = load_policy()

    for attempt in range(MAX_TRIES):
        # Prompt for username
        if username_arg:
            username = username_arg
        else:
            try:
                username = input('\nlogin: ').strip()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(3)

        if not username:
            username_arg = None
            continue

        p_entry = pdb.get_by_name(username)
        s_entry = sdb.get(username) if p_entry else None

        if p_entry is None:
            # User does not exist — fake the verify step to prevent enumeration
            _fake_verify_sleep()
            password = _get_tty_password('Password: ')
            _fake_verify_sleep()
            print('Login incorrect.')
            time.sleep(1 + attempt)
            username_arg = None
            continue

        # Check account expiry
        if s_entry and s_entry.is_expired():
            print('Login failed: account has expired.', file=sys.stderr)
            sys.exit(2)

        # Check faillock
        fl = FailLock(username)
        if fl.is_locked_out(lo_policy):
            secs = fl.seconds_until_unlocked(lo_policy)
            if secs is not None:
                print(
                    f'Account temporarily locked. Try again in {secs} second(s).',
                    file=sys.stderr,
                )
            else:
                print('Account locked. Contact your administrator.', file=sys.stderr)
            sys.exit(2)

        # Prompt for password
        if s_entry and s_entry.has_no_password():
            # Passwordless login (only if account isn't fully disabled)
            password = ''
            authenticated = True
        else:
            password = _get_tty_password('Password: ')
            authenticated = verify_password(password, s_entry.hashed_password if s_entry else '!!')

        if not authenticated:
            fl.record_failure(source=os.environ.get('SSH_TTY', os.ttyname(0) if sys.stdin.isatty() else ''))
            print('Login incorrect.')
            time.sleep(1 + attempt)
            username_arg = None
            continue

        # Authentication successful
        fl.reset()

        # Check must-change-password
        if s_entry and s_entry.must_change_password():
            _inline_password_change(username, p_entry.uid)

        # Warn about password expiry
        if s_entry and s_entry.max_age is not None and s_entry.last_changed is not None:
            days_left = (s_entry.last_changed + s_entry.max_age) - days_since_epoch()
            warn = s_entry.warn_days or pw_policy.warn_days
            if 0 < days_left <= warn:
                print(f'Warning: your password will expire in {days_left} day(s).')

        # Build environment
        env = {
            'HOME': p_entry.home,
            'SHELL': p_entry.shell,
            'USER': p_entry.username,
            'LOGNAME': p_entry.username,
            'PATH': DEFAULT_PATH,
        }
        # Preserve TERM if set
        if 'TERM' in os.environ:
            env['TERM'] = os.environ['TERM']

        # Drop privileges
        try:
            drop_privileges(p_entry.uid, p_entry.gid)
        except OSError as exc:
            print(f'login: failed to drop privileges: {exc}', file=sys.stderr)
            sys.exit(3)

        # Print motd
        _print_file(paths.motd_path)

        # Execute shell
        try:
            os.chdir(p_entry.home)
        except OSError:
            os.chdir('/')

        try:
            os.execvpe(p_entry.shell, [p_entry.shell], env)
        except OSError as exc:
            print(f'login: cannot exec {p_entry.shell!r}: {exc}', file=sys.stderr)
            sys.exit(3)

    # Exhausted retries
    print('Maximum number of tries exceeded (3).', file=sys.stderr)
    sys.exit(1)


if __name__ == '__main__':
    main()
