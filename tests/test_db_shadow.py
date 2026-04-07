"""Tests for login_tools.db.shadow"""
from __future__ import annotations

from datetime import date

import pytest

from login_tools.db.shadow import ShadowDb, ShadowEntry, ShadowNotFoundError, days_since_epoch


def _make_db(root):
    return ShadowDb(root / 'etc' / 'shadow')


class TestShadowEntry:
    def test_is_locked_real_hash(self):
        e = ShadowEntry('u', '!$6$salt$abc', 19000, 0, 99999, 7, None, None, '')
        assert e.is_locked() is True

    def test_is_locked_markers_not_locked(self):
        for h in ('!', '!!', '*'):
            e = ShadowEntry('u', h, 19000, 0, 99999, 7, None, None, '')
            assert e.is_locked() is False, f'{h!r} should not be considered locked'

    def test_has_no_password(self):
        for h in ('!', '!!', '*', ''):
            e = ShadowEntry('u', h, 19000, 0, 99999, 7, None, None, '')
            assert e.has_no_password() is True

    def test_must_change_password(self):
        e = ShadowEntry('u', '$6$x', 0, 0, 99999, 7, None, None, '')
        assert e.must_change_password() is True
        e.last_changed = 19000
        assert e.must_change_password() is False

    def test_is_expired_true(self):
        e = ShadowEntry('u', '$6$x', 19000, 0, 99999, 7, None, 1, '')  # epoch day 1 is in the past
        assert e.is_expired() is True

    def test_is_expired_false(self):
        far_future = days_since_epoch() + 365
        e = ShadowEntry('u', '$6$x', 19000, 0, 99999, 7, None, far_future, '')
        assert e.is_expired() is False

    def test_is_expired_no_date(self):
        e = ShadowEntry('u', '$6$x', 19000, 0, 99999, 7, None, None, '')
        assert e.is_expired() is False

    def test_roundtrip(self):
        original = ShadowEntry('alice', '$6$salt$abc123', 19000, 1, 90, 7, 30, None, '')
        line = original.to_line()
        parsed = ShadowEntry.from_line(line)
        assert parsed.username == original.username
        assert parsed.hashed_password == original.hashed_password
        assert parsed.last_changed == original.last_changed
        assert parsed.min_age == original.min_age
        assert parsed.max_age == original.max_age

    def test_empty_fields_roundtrip(self):
        original = ShadowEntry('root', '!!', None, None, None, None, None, None, '')
        line = original.to_line()
        parsed = ShadowEntry.from_line(line)
        assert parsed.last_changed is None
        assert parsed.expire_date is None


class TestShadowDb:
    def test_load_existing(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        entries = db.load()
        assert len(entries) == 2
        usernames = {e.username for e in entries}
        assert 'root' in usernames
        assert 'alice' in usernames

    def test_get_existing(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        e = db.get('alice')
        assert e is not None
        assert e.username == 'alice'

    def test_get_missing(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        assert db.get('nobody') is None

    def test_add_and_remove(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        entry = ShadowEntry.new_blank('bob')
        db.add(entry)
        assert db.get('bob') is not None
        db.remove('bob')
        assert db.get('bob') is None

    def test_remove_missing_raises(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        with pytest.raises(ShadowNotFoundError):
            db.remove('nobody')

    def test_lock_and_unlock(self, blueyos_root, as_root):
        from login_tools._compat_crypt import hash_password
        db = _make_db(blueyos_root)
        h = hash_password('alicepass')
        db.set_password('alice', h)

        db.lock('alice')
        e = db.get('alice')
        assert e.hashed_password.startswith('!')
        assert e.is_locked() is True

        db.unlock('alice')
        e = db.get('alice')
        assert not e.hashed_password.startswith('!')
        assert e.is_locked() is False

    def test_lock_no_op_on_disabled(self, blueyos_root, as_root):
        db = _make_db(blueyos_root)
        # root has '!!' — lock should not prefix another '!'
        db.lock('root')
        e = db.get('root')
        assert e.hashed_password == '!!'

    def test_set_password_updates_last_changed(self, blueyos_root, as_root):
        from login_tools._compat_crypt import hash_password
        db = _make_db(blueyos_root)
        today = days_since_epoch()
        db.set_password('alice', hash_password('newpass'))
        e = db.get('alice')
        assert e.last_changed == today
