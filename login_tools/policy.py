"""
Password and lockout policy engine.

Policies are read from /etc/security/pwpolicy.conf (INI format).
Missing file or missing keys silently fall back to safe defaults.
"""
from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path

from login_tools import paths
from login_tools.atomic import atomic_write_text, db_lock


@dataclass
class PasswordPolicy:
    min_length: int = 8
    max_length: int = 256        # 0 = no limit
    require_uppercase: int = 0   # minimum count of uppercase letters
    require_lowercase: int = 0
    require_digits: int = 0
    require_special: int = 0
    min_classes: int = 0         # minimum distinct character classes (0 = disabled)
    forbidden_words: list[str] = field(default_factory=list)
    history_count: int = 0       # prevent reuse of last N passwords (0 = disabled)
    max_age_days: int | None = None
    min_age_days: int = 0
    warn_days: int = 7


@dataclass
class LockoutPolicy:
    max_attempts: int = 5        # 0 = disabled
    lockout_duration: int = 300  # seconds; 0 = permanent until admin resets
    window: int = 300            # sliding window in seconds


def load_policy(path: Path | None = None) -> tuple[PasswordPolicy, LockoutPolicy]:
    """
    Parse /etc/security/pwpolicy.conf.
    Returns (PasswordPolicy, LockoutPolicy) with defaults for missing values.
    """
    config_path = path or paths.pwpolicy_path()
    cfg = configparser.ConfigParser(inline_comment_prefixes=('#',))
    cfg.read(config_path)  # silently ignores missing file

    def _get_int(section: str, key: str, default: int) -> int:
        try:
            return cfg.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def _get_str(section: str, key: str, default: str) -> str:
        try:
            return cfg.get(section, key).strip()
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    max_age_raw = _get_int('password', 'max_age_days', -1)
    max_age = max_age_raw if max_age_raw >= 0 else None

    forbidden_raw = _get_str('password', 'forbidden_words', '')
    forbidden_words = [w.strip() for w in forbidden_raw.split(',') if w.strip()]

    pw_policy = PasswordPolicy(
        min_length=_get_int('password', 'min_length', 8),
        max_length=_get_int('password', 'max_length', 256),
        require_uppercase=_get_int('password', 'require_uppercase', 0),
        require_lowercase=_get_int('password', 'require_lowercase', 0),
        require_digits=_get_int('password', 'require_digits', 0),
        require_special=_get_int('password', 'require_special', 0),
        min_classes=_get_int('password', 'min_classes', 0),
        forbidden_words=forbidden_words,
        history_count=_get_int('password', 'history_count', 0),
        max_age_days=max_age,
        min_age_days=_get_int('password', 'min_age_days', 0),
        warn_days=_get_int('password', 'warn_days', 7),
    )

    lo_policy = LockoutPolicy(
        max_attempts=_get_int('lockout', 'max_attempts', 5),
        lockout_duration=_get_int('lockout', 'lockout_duration', 300),
        window=_get_int('lockout', 'window', 300),
    )

    return pw_policy, lo_policy


def check_password_complexity(
    password: str,
    policy: PasswordPolicy,
    username: str = '',
) -> list[str]:
    """
    Validate *password* against *policy*.
    Returns a list of human-readable violation messages.
    Empty list means the password is acceptable.
    """
    violations: list[str] = []

    length = len(password)
    if length < policy.min_length:
        violations.append(
            f'Password is too short (minimum {policy.min_length} characters, got {length}).'
        )
    if policy.max_length > 0 and length > policy.max_length:
        violations.append(
            f'Password is too long (maximum {policy.max_length} characters).'
        )

    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum() and c.isprintable())

    if policy.require_uppercase and upper < policy.require_uppercase:
        violations.append(
            f'Password must contain at least {policy.require_uppercase} uppercase letter(s).'
        )
    if policy.require_lowercase and lower < policy.require_lowercase:
        violations.append(
            f'Password must contain at least {policy.require_lowercase} lowercase letter(s).'
        )
    if policy.require_digits and digits < policy.require_digits:
        violations.append(
            f'Password must contain at least {policy.require_digits} digit(s).'
        )
    if policy.require_special and special < policy.require_special:
        violations.append(
            f'Password must contain at least {policy.require_special} special character(s).'
        )

    if policy.min_classes > 0:
        classes_present = sum([
            1 if upper > 0 else 0,
            1 if lower > 0 else 0,
            1 if digits > 0 else 0,
            1 if special > 0 else 0,
        ])
        if classes_present < policy.min_classes:
            violations.append(
                f'Password must use at least {policy.min_classes} character class(es) '
                f'(uppercase, lowercase, digits, special). Got {classes_present}.'
            )

    pw_lower = password.lower()
    for word in policy.forbidden_words:
        if word.lower() in pw_lower:
            violations.append(f"Password must not contain the word '{word}'.")

    if username and username.lower() in pw_lower:
        violations.append('Password must not contain your username.')

    return violations


def _opasswd_read(username: str, opasswd_path: Path) -> list[str]:
    """Read stored hashes for *username* from opasswd. Returns list of hash strings."""
    try:
        text = opasswd_path.read_text()
    except FileNotFoundError:
        return []
    for line in text.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[0] == username:
            return [h for h in parts[3].split(',') if h]
    return []


def check_password_history(
    username: str,
    new_password: str,
    policy: PasswordPolicy,
    opasswd_path: Path | None = None,
) -> bool:
    """
    Return True if *new_password* matches any of the last *history_count*
    stored password hashes for *username*.
    """
    if policy.history_count <= 0:
        return False
    from login_tools._compat_crypt import verify_password
    path = opasswd_path or paths.opasswd_path()
    hashes = _opasswd_read(username, path)
    for stored_hash in hashes[:policy.history_count]:
        if verify_password(new_password, stored_hash):
            return True
    return False


def record_password_history(
    username: str,
    uid: int,
    old_hash: str,
    policy: PasswordPolicy,
    opasswd_path: Path | None = None,
) -> None:
    """
    Prepend *old_hash* to the opasswd history for *username*,
    trimming to *policy.history_count* entries.

    opasswd line format: username:uid:count:hash1,hash2,...hashN
    """
    if policy.history_count <= 0:
        return
    opath = opasswd_path or paths.opasswd_path()
    with db_lock(opath):
        try:
            text = opath.read_text()
        except FileNotFoundError:
            text = ''
        lines = text.splitlines()
        new_lines: list[str] = []
        updated = False
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 1 and parts[0] == username:
                hashes = [h for h in (parts[3].split(',') if len(parts) >= 4 else []) if h]
                hashes.insert(0, old_hash)
                hashes = hashes[:policy.history_count]
                new_lines.append(f'{username}:{uid}:{len(hashes)}:{",".join(hashes)}')
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            new_lines.append(f'{username}:{uid}:1:{old_hash}')
        content = '\n'.join(new_lines) + '\n'
        atomic_write_text(opath, content, mode=0o600)
