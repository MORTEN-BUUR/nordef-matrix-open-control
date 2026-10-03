from __future__ import annotations

import os
import stat
from pathlib import Path


class SandboxError(RuntimeError):
    pass


def check_runtime(state_dir: str | Path, *, allow_root: bool = False, euid: int | None = None) -> None:
    """Refuse to serve from an unsafe runtime.

    - not as root (a compromised server process must not own the host);
    - state directory owned by the service UID and not group/world-writable,
      so another local account cannot rewrite evidence or replay state.
    """
    uid = os.geteuid() if euid is None else euid
    if uid == 0 and not allow_root:
        raise SandboxError("refusing_to_run_as_root")
    path = Path(state_dir)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != uid:
        raise SandboxError("state_dir_not_owned_by_service_uid")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SandboxError("state_dir_group_or_world_writable")
