"""Tests for login_tools.faillock"""
from __future__ import annotations

import time

import pytest

from login_tools.faillock import FailLock
from login_tools.policy import LockoutPolicy


@pytest.fixture
def fl(tmp_path):
    return FailLock('alice', dir_path=tmp_path / 'faillock')


@pytest.fixture
def policy():
    return LockoutPolicy(max_attempts=3, lockout_duration=60, window=300)


class TestFailLock:
    def test_initially_not_locked(self, fl, policy):
        assert fl.is_locked_out(policy) is False
        assert fl.failure_count(policy) == 0

    def test_below_threshold_not_locked(self, fl, policy):
        fl.record_failure()
        fl.record_failure()
        assert fl.failure_count(policy) == 2
        assert fl.is_locked_out(policy) is False

    def test_at_threshold_is_locked(self, fl, policy):
        fl.record_failure()
        fl.record_failure()
        fl.record_failure()
        assert fl.is_locked_out(policy) is True

    def test_reset_clears_lockout(self, fl, policy):
        fl.record_failure()
        fl.record_failure()
        fl.record_failure()
        assert fl.is_locked_out(policy) is True
        fl.reset()
        assert fl.is_locked_out(policy) is False
        assert fl.failure_count(policy) == 0

    def test_disabled_policy_never_locks(self, fl):
        policy = LockoutPolicy(max_attempts=0)
        for _ in range(100):
            fl.record_failure()
        assert fl.is_locked_out(policy) is False

    def test_permanent_lockout(self, fl):
        policy = LockoutPolicy(max_attempts=2, lockout_duration=0, window=300)
        fl.record_failure()
        fl.record_failure()
        assert fl.is_locked_out(policy) is True

    def test_lockout_expires(self, fl):
        policy = LockoutPolicy(max_attempts=2, lockout_duration=1, window=300)
        fl.record_failure()
        fl.record_failure()
        assert fl.is_locked_out(policy) is True
        time.sleep(1.1)
        assert fl.is_locked_out(policy) is False

    def test_window_excludes_old_failures(self, fl, monkeypatch):
        """Failures outside the window should not count."""
        old_time = time.time() - 400  # outside the 300s window
        import login_tools.faillock as fmod
        call_count = [0]
        original_time = time.time

        def fake_time():
            call_count[0] += 1
            return old_time

        monkeypatch.setattr(fmod.time, 'time', fake_time)
        fl.record_failure()
        fl.record_failure()
        fl.record_failure()

        monkeypatch.setattr(fmod.time, 'time', original_time)
        policy = LockoutPolicy(max_attempts=3, lockout_duration=60, window=300)
        assert fl.failure_count(policy) == 0
        assert fl.is_locked_out(policy) is False

    def test_seconds_until_unlocked(self, fl, policy):
        fl.record_failure()
        fl.record_failure()
        fl.record_failure()
        secs = fl.seconds_until_unlocked(policy)
        assert secs is not None
        assert secs > 0
        assert secs <= 61

    def test_seconds_until_unlocked_permanent(self, fl):
        policy = LockoutPolicy(max_attempts=2, lockout_duration=0, window=300)
        fl.record_failure()
        fl.record_failure()
        assert fl.seconds_until_unlocked(policy) is None

    def test_source_recorded(self, fl, policy):
        fl.record_failure(source='tty1')
        record = fl._load()
        assert record.attempts[0].source == 'tty1'
