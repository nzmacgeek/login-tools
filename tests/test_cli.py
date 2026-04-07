"""Tests for CLI tools"""
from __future__ import annotations

import sys
import pytest

from login_tools._compat_crypt import hash_password, verify_password
from login_tools.db.shadow import ShadowDb, days_since_epoch


class TestSetupRoot:
    def test_sets_root_password_when_unset(self, blueyos_root, mock_getpass):
        mock_getpass(['Str@ngPass1!', 'Str@ngPass1!'])
        from login_tools.cli.setup_root import main
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        sdb = ShadowDb(blueyos_root / 'etc' / 'shadow')
        e = sdb.get('root')
        assert verify_password('Str@ngPass1!', e.hashed_password)

    def test_refuses_if_root_already_has_password(self, blueyos_root):
        # Set root password first
        sdb = ShadowDb(blueyos_root / 'etc' / 'shadow')
        sdb.set_password('root', hash_password('existingPassword1!'))

        from login_tools.cli.setup_root import main
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_rejects_mismatched_passwords(self, blueyos_root, mock_getpass):
        mock_getpass(['ValidPass1!', 'DifferentPass1!'])
        from login_tools.cli.setup_root import main
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    def test_rejects_weak_password(self, blueyos_root, mock_getpass):
        mock_getpass(['weak', 'weak'])
        from login_tools.cli.setup_root import main
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3


class TestPasswdCLI:
    def test_root_changes_other_user_password(
        self, blueyos_root, as_root, mock_getpass
    ):
        new_pw = 'Str@ngNewPass1!'
        mock_getpass([new_pw, new_pw])
        from login_tools.cli import passwd as passwd_mod
        sys.argv = ['passwd', 'alice']
        with pytest.raises(SystemExit) as exc:
            passwd_mod.main()
        assert exc.value.code == 0
        sdb = ShadowDb(blueyos_root / 'etc' / 'shadow')
        e = sdb.get('alice')
        assert verify_password(new_pw, e.hashed_password)

    def test_lock_and_unlock(self, blueyos_root, as_root):
        from login_tools.cli import passwd as passwd_mod

        sys.argv = ['passwd', '--lock', 'alice']
        with pytest.raises(SystemExit) as exc:
            passwd_mod.main()
        assert exc.value.code == 0
        sdb = ShadowDb(blueyos_root / 'etc' / 'shadow')
        assert sdb.get('alice').is_locked()

        sys.argv = ['passwd', '--unlock', 'alice']
        with pytest.raises(SystemExit) as exc:
            passwd_mod.main()
        assert exc.value.code == 0
        assert not sdb.get('alice').is_locked()

    def test_non_root_cannot_change_other_user(self, blueyos_root, as_alice):
        from login_tools.cli import passwd as passwd_mod
        sys.argv = ['passwd', 'root']
        with pytest.raises(SystemExit) as exc:
            passwd_mod.main()
        assert exc.value.code == 1


class TestUseradd:
    def test_creates_user(self, blueyos_root, as_root):
        from login_tools.cli.useradd import main
        sys.argv = ['useradd', '-m', 'bob']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        from login_tools.db.passwd import PasswdDb
        pdb = PasswdDb(blueyos_root / 'etc' / 'passwd')
        assert pdb.get_by_name('bob') is not None

    def test_duplicate_fails(self, blueyos_root, as_root):
        from login_tools.cli.useradd import main
        sys.argv = ['useradd', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3


class TestUserdel:
    def test_removes_user(self, blueyos_root, as_root):
        from login_tools.cli.userdel import main
        sys.argv = ['userdel', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        from login_tools.db.passwd import PasswdDb
        pdb = PasswdDb(blueyos_root / 'etc' / 'passwd')
        assert pdb.get_by_name('alice') is None

    def test_missing_user_fails(self, blueyos_root, as_root):
        from login_tools.cli.userdel import main
        sys.argv = ['userdel', 'nobody']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3


class TestGroupadd:
    def test_creates_group(self, blueyos_root, as_root):
        from login_tools.cli.groupadd import main
        sys.argv = ['groupadd', 'devs']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        from login_tools.db.group import GroupDb
        gdb = GroupDb(blueyos_root / 'etc' / 'group')
        assert gdb.get_by_name('devs') is not None


class TestGroupdel:
    def test_deletes_group(self, blueyos_root, as_root):
        # Add a new group first
        from login_tools.db.group import GroupDb, GroupEntry
        gdb = GroupDb(blueyos_root / 'etc' / 'group')
        gdb.add(GroupEntry('devs', 'x', 2000, []))

        from login_tools.cli.groupdel import main
        sys.argv = ['groupdel', 'devs']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        assert gdb.get_by_name('devs') is None

    def test_refuses_primary_group(self, blueyos_root, as_root):
        from login_tools.cli.groupdel import main
        # 'alice' group (gid=1000) is alice's primary group
        sys.argv = ['groupdel', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 8


class TestChsh:
    def test_root_changes_any_shell(self, blueyos_root, as_root):
        from login_tools.cli.chsh import main
        sys.argv = ['chsh', '-s', '/bin/bash', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        from login_tools.db.passwd import PasswdDb
        pdb = PasswdDb(blueyos_root / 'etc' / 'passwd')
        assert pdb.get_by_name('alice').shell == '/bin/bash'

    def test_non_root_cannot_use_unlisted_shell(self, blueyos_root, as_alice, monkeypatch):
        monkeypatch.setattr('login_tools.privilege.get_current_username', lambda: 'alice')
        from login_tools.cli.chsh import main
        sys.argv = ['chsh', '-s', '/bin/zsh', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 4

    def test_list_shells(self, blueyos_root, capsys):
        from login_tools.cli.chsh import main
        sys.argv = ['chsh', '-l']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert '/bin/sh' in out


class TestUserlock:
    def test_lock_unlock_status(self, blueyos_root, as_root):
        from login_tools.cli.userlock import main

        sys.argv = ['userlock', '--lock', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        sdb = ShadowDb(blueyos_root / 'etc' / 'shadow')
        assert sdb.get('alice').is_locked()

        sys.argv = ['userlock', '--unlock', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        assert not sdb.get('alice').is_locked()

    def test_reset_faillock(self, blueyos_root, as_root):
        from login_tools.faillock import FailLock
        from login_tools.policy import LockoutPolicy
        fl = FailLock('alice', blueyos_root / 'var' / 'run' / 'faillock')
        fl.record_failure()
        fl.record_failure()
        fl.record_failure()

        from login_tools.cli.userlock import main
        sys.argv = ['userlock', '--reset-faillock', 'alice']
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        assert fl.failure_count(LockoutPolicy()) == 0
