"""
Shared pytest fixtures for blueyos-login-tools.

All file operations are redirected to a temporary directory via BLUEYOS_ROOT,
so the entire test suite runs without root access.
"""
from __future__ import annotations

import pytest
from pathlib import Path

from login_tools._compat_crypt import hash_password


# Pre-compute a known hash for Alice's password 'alicepass'
ALICE_PASSWORD = 'alicepass'


@pytest.fixture
def blueyos_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """
    Create a minimal fake BLUEYOS_ROOT and set the env var.
    All login_tools.paths functions return paths under tmp_path.
    """
    root = tmp_path

    # Create directory structure
    (root / 'etc').mkdir()
    (root / 'etc' / 'security').mkdir()
    (root / 'var' / 'run' / 'faillock').mkdir(parents=True)
    (root / 'home' / 'alice').mkdir(parents=True)

    alice_hash = hash_password(ALICE_PASSWORD)

    # Minimal /etc/passwd
    (root / 'etc' / 'passwd').write_text(
        'root:x:0:0:root:/root:/bin/bash\n'
        'alice:x:1000:1000:Alice:/home/alice:/bin/sh\n'
    )

    # /etc/shadow: root has no password (!!), alice has a real hash
    (root / 'etc' / 'shadow').write_text(
        f'root:!!:19000:0:99999:7:::\n'
        f'alice:{alice_hash}:19000:0:99999:7:::\n'
    )

    # /etc/group
    (root / 'etc' / 'group').write_text(
        'root:x:0:\n'
        'alice:x:1000:alice\n'
    )

    # /etc/shells
    (root / 'etc' / 'shells').write_text('/bin/sh\n/bin/bash\n')

    monkeypatch.setenv('BLUEYOS_ROOT', str(root))
    return root


@pytest.fixture
def as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make privilege checks believe we are running as root."""
    monkeypatch.setattr('login_tools.privilege.get_effective_uid', lambda: 0)


@pytest.fixture
def as_alice(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make privilege checks believe we are running as alice (UID 1000)."""
    monkeypatch.setattr('login_tools.privilege.get_effective_uid', lambda: 1000)


@pytest.fixture
def mock_getpass(monkeypatch: pytest.MonkeyPatch):
    """
    Returns a factory function to configure what getpass.getpass returns.
    Usage:
        mock_getpass(['password1', 'password2'])  # successive calls
    """
    def _setup(passwords: list[str]) -> None:
        it = iter(passwords)
        monkeypatch.setattr('getpass.getpass', lambda prompt='': next(it))
    return _setup
