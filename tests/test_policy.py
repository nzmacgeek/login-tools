"""Tests for login_tools.policy"""
from __future__ import annotations

import pytest

from login_tools.policy import (
    LockoutPolicy,
    PasswordPolicy,
    check_password_complexity,
    load_policy,
    check_password_history,
    record_password_history,
)


class TestPasswordComplexity:
    def _policy(self, **kwargs) -> PasswordPolicy:
        return PasswordPolicy(**kwargs)

    def test_min_length_pass(self):
        p = self._policy(min_length=8)
        assert check_password_complexity('12345678', p) == []

    def test_min_length_fail(self):
        p = self._policy(min_length=8)
        violations = check_password_complexity('short', p)
        assert any('too short' in v for v in violations)

    def test_max_length_fail(self):
        p = self._policy(max_length=10)
        violations = check_password_complexity('a' * 11, p)
        assert any('too long' in v for v in violations)

    def test_max_length_zero_no_limit(self):
        p = self._policy(max_length=0)
        assert check_password_complexity('a' * 1000, p) == []

    def test_require_uppercase(self):
        p = self._policy(require_uppercase=1, min_length=1)
        assert check_password_complexity('nouppercase', p) != []
        assert check_password_complexity('HasUpper', p) == []

    def test_require_lowercase(self):
        p = self._policy(require_lowercase=1, min_length=1)
        assert check_password_complexity('NOLOWER', p) != []
        assert check_password_complexity('HasLower', p) == []

    def test_require_digits(self):
        p = self._policy(require_digits=1, min_length=1)
        assert check_password_complexity('NoDigit!', p) != []
        assert check_password_complexity('HasDigit1', p) == []

    def test_require_special(self):
        p = self._policy(require_special=1, min_length=1)
        assert check_password_complexity('NoSpecial1', p) != []
        assert check_password_complexity('HasSpec!al1', p) == []

    def test_min_classes_pass(self):
        p = self._policy(min_classes=3, min_length=1)
        # uppercase + lowercase + digit = 3 classes
        assert check_password_complexity('Abc123', p) == []

    def test_min_classes_fail(self):
        p = self._policy(min_classes=3, min_length=1)
        # only lowercase
        violations = check_password_complexity('alllower', p)
        assert any('class' in v for v in violations)

    def test_forbidden_word(self):
        p = self._policy(forbidden_words=['password'])
        violations = check_password_complexity('myPassword123', p)
        assert any('password' in v.lower() for v in violations)

    def test_username_check(self):
        p = self._policy(min_length=1)
        violations = check_password_complexity('aliceRocks!', p, username='alice')
        assert any('username' in v for v in violations)

    def test_all_pass(self):
        p = PasswordPolicy(
            min_length=8,
            require_uppercase=1,
            require_lowercase=1,
            require_digits=1,
            require_special=1,
        )
        assert check_password_complexity('MyP@ssw0rd!', p, username='bob') == []


class TestLoadPolicy:
    def test_defaults_on_missing_file(self, tmp_path):
        pw, lo = load_policy(tmp_path / 'nonexistent.conf')
        assert pw.min_length == 8
        assert lo.max_attempts == 5

    def test_custom_values(self, tmp_path):
        cfg = tmp_path / 'pwpolicy.conf'
        cfg.write_text('[password]\nmin_length = 12\n[lockout]\nmax_attempts = 3\n')
        pw, lo = load_policy(cfg)
        assert pw.min_length == 12
        assert lo.max_attempts == 3

    def test_forbidden_words_parsed(self, tmp_path):
        cfg = tmp_path / 'pwpolicy.conf'
        cfg.write_text('[password]\nforbidden_words = foo,bar,baz\n')
        pw, _ = load_policy(cfg)
        assert 'foo' in pw.forbidden_words
        assert 'baz' in pw.forbidden_words

    def test_partial_section(self, tmp_path):
        cfg = tmp_path / 'pwpolicy.conf'
        cfg.write_text('[password]\nmin_length = 10\n')
        pw, lo = load_policy(cfg)
        assert pw.min_length == 10
        assert lo.max_attempts == 5  # still default


class TestPasswordHistory:
    def test_no_history_never_matches(self, tmp_path):
        p = PasswordPolicy(history_count=0)
        assert check_password_history('alice', 'anypassword', p, tmp_path / 'opasswd') is False

    def test_detects_reused_password(self, tmp_path):
        from login_tools._compat_crypt import hash_password
        p = PasswordPolicy(history_count=3)
        old_hash = hash_password('oldpassword')
        record_password_history('alice', 1000, old_hash, p, tmp_path / 'opasswd')
        assert check_password_history('alice', 'oldpassword', p, tmp_path / 'opasswd') is True

    def test_allows_new_password(self, tmp_path):
        from login_tools._compat_crypt import hash_password
        p = PasswordPolicy(history_count=3)
        old_hash = hash_password('oldpassword')
        record_password_history('alice', 1000, old_hash, p, tmp_path / 'opasswd')
        assert check_password_history('alice', 'brandnewpassword', p, tmp_path / 'opasswd') is False

    def test_history_trimmed_to_count(self, tmp_path):
        from login_tools._compat_crypt import hash_password
        p = PasswordPolicy(history_count=2)
        opasswd = tmp_path / 'opasswd'
        for pw in ['pw1', 'pw2', 'pw3']:
            record_password_history('alice', 1000, hash_password(pw), p, opasswd)
        # pw1 should have been trimmed — only pw2 and pw3 kept
        text = opasswd.read_text()
        # count commas: should have at most 1 comma (2 hashes)
        parts = [line for line in text.splitlines() if line.startswith('alice:')]
        assert len(parts) == 1
        hashes_part = parts[0].split(':')[3]
        assert len(hashes_part.split(',')) == 2
