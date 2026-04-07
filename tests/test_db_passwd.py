"""Tests for login_tools.db.passwd and login_tools.db.group"""
from __future__ import annotations

import pytest

from login_tools.db.passwd import PasswdDb, PasswdEntry, UserExistsError, UIDInUseError, UserNotFoundError
from login_tools.db.group import GroupDb, GroupEntry, GroupExistsError, GroupNotFoundError


class TestPasswdDb:
    def _db(self, root):
        return PasswdDb(root / 'etc' / 'passwd')

    def test_load(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        entries = db.load()
        assert len(entries) == 2

    def test_get_by_name(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        assert db.get_by_name('alice') is not None
        assert db.get_by_name('nobody') is None

    def test_get_by_uid(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        assert db.get_by_uid(1000) is not None
        assert db.get_by_uid(9999) is None

    def test_add_and_remove(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        bob = PasswdEntry('bob', 'x', 1001, 1001, '', '/home/bob', '/bin/sh')
        db.add(bob)
        assert db.get_by_name('bob') is not None
        db.remove('bob')
        assert db.get_by_name('bob') is None

    def test_add_duplicate_raises(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        dup = PasswdEntry('alice', 'x', 9999, 9999, '', '/home/alice', '/bin/sh')
        with pytest.raises(UserExistsError):
            db.add(dup)

    def test_add_uid_in_use_raises(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        dup = PasswdEntry('newuser', 'x', 1000, 1000, '', '/home/newuser', '/bin/sh')
        with pytest.raises(UIDInUseError):
            db.add(dup)

    def test_remove_missing_raises(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        with pytest.raises(UserNotFoundError):
            db.remove('nobody')

    def test_update(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        entry = db.get_by_name('alice')
        entry.shell = '/bin/bash'
        db.update(entry)
        assert db.get_by_name('alice').shell == '/bin/bash'

    def test_next_uid(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        uid = db.next_uid()
        assert uid >= 1000
        assert db.get_by_uid(uid) is None

    def test_validate_username_valid(self):
        PasswdDb.validate_username('alice')
        PasswdDb.validate_username('_sysuser')
        PasswdDb.validate_username('user-name')

    def test_validate_username_invalid(self):
        with pytest.raises(ValueError):
            PasswdDb.validate_username('1invalid')
        with pytest.raises(ValueError):
            PasswdDb.validate_username('has space')
        with pytest.raises(ValueError):
            PasswdDb.validate_username('HAS_UPPER')


class TestGroupDb:
    def _db(self, root):
        return GroupDb(root / 'etc' / 'group')

    def test_load(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        entries = db.load()
        assert len(entries) == 2

    def test_add_member(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        db.add_member('root', 'alice')
        e = db.get_by_name('root')
        assert 'alice' in e.members

    def test_remove_member(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        db.add_member('root', 'alice')
        db.remove_member('root', 'alice')
        e = db.get_by_name('root')
        assert 'alice' not in e.members

    def test_groups_for_user(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        groups = db.groups_for_user('alice')
        names = {g.groupname for g in groups}
        assert 'alice' in names

    def test_remove_user_from_all_groups(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        db.add_member('root', 'alice')
        db.remove_user_from_all_groups('alice')
        for g in db.load():
            assert 'alice' not in g.members

    def test_add_group_exists_raises(self, blueyos_root, as_root):
        db = self._db(blueyos_root)
        with pytest.raises(GroupExistsError):
            db.add(GroupEntry('root', 'x', 999, []))

    def test_primary_group_check(self, blueyos_root, as_root):
        pdb = PasswdDb(blueyos_root / 'etc' / 'passwd')
        gdb = self._db(blueyos_root)
        assert gdb.is_primary_group_of_any_user(1000, pdb) is True   # alice's primary gid
        assert gdb.is_primary_group_of_any_user(9999, pdb) is False
