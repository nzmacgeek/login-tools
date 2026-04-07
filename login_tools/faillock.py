"""
Per-user failed login attempt tracking.

Each user's failures are stored as a JSON file at /var/run/faillock/<username>.
The /var/run/ directory is typically tmpfs — lockouts reset on reboot.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from login_tools import paths
from login_tools.atomic import atomic_write_text, db_lock
from login_tools.policy import LockoutPolicy


@dataclass
class FailAttempt:
    timestamp: float   # time.time()
    source: str        # tty name or remote IP, may be empty string


@dataclass
class FailRecord:
    version: int
    attempts: list[FailAttempt]

    def to_json(self) -> str:
        return json.dumps({
            'version': self.version,
            'attempts': [
                {'timestamp': a.timestamp, 'source': a.source}
                for a in self.attempts
            ],
        }, indent=2)

    @classmethod
    def from_json(cls, text: str) -> FailRecord:
        data = json.loads(text)
        attempts = [
            FailAttempt(timestamp=a['timestamp'], source=a.get('source', ''))
            for a in data.get('attempts', [])
        ]
        return cls(version=data.get('version', 1), attempts=attempts)

    @classmethod
    def empty(cls) -> FailRecord:
        return cls(version=1, attempts=[])


class FailLock:
    def __init__(self, username: str, dir_path: Path | None = None) -> None:
        self._dir = dir_path or paths.faillock_dir()
        self._path = self._dir / username
        self._username = username

    def _load(self) -> FailRecord:
        try:
            return FailRecord.from_json(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return FailRecord.empty()

    def _save(self, record: FailRecord) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self._path, record.to_json(), mode=0o600)

    def record_failure(self, source: str = '') -> None:
        """Append a new failed attempt. Thread-safe via db_lock."""
        with db_lock(self._path):
            record = self._load()
            record.attempts.append(FailAttempt(timestamp=time.time(), source=source))
            self._save(record)

    def reset(self) -> None:
        """Remove the faillock file, clearing all recorded failures."""
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass

    def recent_failures(self, policy: LockoutPolicy) -> list[FailAttempt]:
        """Return attempts within the lookback window.
        If window == 0, returns all attempts."""
        record = self._load()
        if policy.window <= 0:
            return record.attempts
        cutoff = time.time() - policy.window
        return [a for a in record.attempts if a.timestamp >= cutoff]

    def is_locked_out(self, policy: LockoutPolicy) -> bool:
        """Return True if the account should be denied based on policy."""
        if policy.max_attempts <= 0:
            return False
        recent = self.recent_failures(policy)
        if len(recent) < policy.max_attempts:
            return False
        # Threshold reached
        if policy.lockout_duration == 0:
            return True  # permanent until admin resets
        most_recent_ts = max(a.timestamp for a in recent)
        lockout_expires = most_recent_ts + policy.lockout_duration
        return time.time() < lockout_expires

    def seconds_until_unlocked(self, policy: LockoutPolicy) -> int | None:
        """
        Returns seconds remaining in lockout, or None if not locked / permanent lockout.
        """
        if policy.max_attempts <= 0 or policy.lockout_duration == 0:
            return None
        recent = self.recent_failures(policy)
        if len(recent) < policy.max_attempts:
            return None
        most_recent_ts = max(a.timestamp for a in recent)
        lockout_expires = most_recent_ts + policy.lockout_duration
        remaining = lockout_expires - time.time()
        if remaining <= 0:
            return None
        return int(remaining) + 1  # round up

    def failure_count(self, policy: LockoutPolicy) -> int:
        """Return number of recent failures within the window."""
        return len(self.recent_failures(policy))
