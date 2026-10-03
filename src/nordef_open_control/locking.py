from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def exclusive_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive advisory lock on ``<path>.lock`` for the duration of the block.

    Serializes read-modify-write cycles on shared state (evidence chain, replay
    registry, license counters) across processes serving the same tenant.
    """
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
