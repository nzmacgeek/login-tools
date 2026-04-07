"""
BLUEYOS_ROOT-aware path helpers.

All helpers are functions (not module-level constants) so that tests can
freely change BLUEYOS_ROOT between calls via monkeypatch.setenv().
"""
import os
from pathlib import Path


def root() -> Path:
    return Path(os.environ.get('BLUEYOS_ROOT', '/'))


def etc() -> Path:
    return root() / 'etc'


def var_run() -> Path:
    return root() / 'var' / 'run'


def home_base() -> Path:
    return root() / 'home'


def passwd_path() -> Path:
    return etc() / 'passwd'


def shadow_path() -> Path:
    return etc() / 'shadow'


def group_path() -> Path:
    return etc() / 'group'


def shells_path() -> Path:
    return etc() / 'shells'


def pwpolicy_path() -> Path:
    return etc() / 'security' / 'pwpolicy.conf'


def opasswd_path() -> Path:
    return etc() / 'security' / 'opasswd'


def faillock_dir() -> Path:
    return var_run() / 'faillock'


def issue_path() -> Path:
    return etc() / 'issue'


def motd_path() -> Path:
    return etc() / 'motd'
