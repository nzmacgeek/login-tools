"""
Atomic file writes and flock-based inter-process locking.
"""
import fcntl
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator


@contextmanager
def db_lock(path: Path) -> Generator[None, None, None]:
    """
    Acquire an exclusive flock on <path>.lock before yielding.
    Creates the lock file if it does not exist.
    Always releases on exit, even on exception.
    """
    lock_path = path.with_name(path.name + '.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, 'a') as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """
    Write *content* to *path* atomically.

    Steps:
    1. Create a named temp file in the same directory (guarantees same filesystem).
    2. Set permissions before rename so the file is never world-readable even
       briefly with wrong perms.
    3. os.replace() — atomic on POSIX, survives a process crash mid-write.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=f'.{path.name}.tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
