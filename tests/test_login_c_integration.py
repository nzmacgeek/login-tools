"""Integration contract tests for the C login binary."""
from __future__ import annotations

import os
import pty
import select
import subprocess
import time
from pathlib import Path


def _build_login_binary(tmp_path: Path) -> Path:
    binary = tmp_path / 'login-c'
    sources = [
        'src/login.c',
        'src/lib/util.c',
        'src/lib/shadow.c',
        'src/lib/passwd_file.c',
        'src/lib/group_file.c',
        'src/lib/policy.c',
        'src/lib/faillock.c',
    ]
    cmd = [
        'gcc',
        '-std=gnu11',
        '-Wall',
        '-Wextra',
        '-O2',
        '-D_GNU_SOURCE',
        '-Isrc',
        '-o',
        str(binary),
        *sources,
        '-lcrypt',
    ]
    subprocess.run(cmd, check=True)
    return binary


def _run_over_pty(cmd: list[str], env: dict[str, str], password: str, timeout: float = 8.0) -> tuple[int, str]:
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        preexec_fn=os.setsid,
        close_fds=True,
    )
    os.close(slave_fd)

    output = bytearray()
    os.write(master_fd, password.encode() + b'\n')
    end_time = time.monotonic() + timeout

    try:
        while time.monotonic() < end_time:
            if proc.poll() is not None:
                break

            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if not readable:
                continue

            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break

            if not chunk:
                break

            output.extend(chunk)

        # Drain any remaining output after process exit.
        while True:
            readable, _, _ = select.select([master_fd], [], [], 0)
            if not readable:
                break
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
    finally:
        os.close(master_fd)

    rc = proc.wait(timeout=2)
    return rc, output.decode(errors='replace')


def test_matey_handoff_contract(blueyos_root: Path, tmp_path: Path) -> None:
    """In --matey-handoff mode, login must print only the authenticated username."""
    binary = _build_login_binary(tmp_path)
    env = dict(os.environ)
    env['BLUEYOS_ROOT'] = str(blueyos_root)

    rc, out = _run_over_pty([str(binary), '--matey-handoff', 'alice'], env, password='alicepass')
    normalized = out.replace('\r', '')

    assert rc == 0, out
    assert normalized.endswith('alice\n')
    assert 'failed to setgid' not in normalized
    assert 'failed to setuid' not in normalized
