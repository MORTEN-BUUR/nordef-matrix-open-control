from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
HALT_FILE = "HALT.json"


class TenantError(ValueError):
    pass


def validate_tenant(tenant: str) -> str:
    if not isinstance(tenant, str) or not _TENANT_RE.fullmatch(tenant):
        raise TenantError("invalid_tenant_id")
    return tenant


@dataclass(frozen=True)
class TenantPaths:
    """Isolated per-tenant state. No path component is ever taken from model input."""

    root: Path
    tenant: str

    @classmethod
    def create(cls, root: str | Path, tenant: str) -> "TenantPaths":
        paths = cls(Path(root), validate_tenant(tenant))
        paths.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return paths

    @property
    def dir(self) -> Path:
        return self.root / "tenants" / self.tenant

    @property
    def replay(self) -> Path:
        return self.dir / "replay.json"

    @property
    def license_meter(self) -> Path:
        return self.root / "license-usage.json"


class HaltSwitch:
    """Human stop button (EU AI Act art. 14(4)(e)).

    A ``HALT.json`` file at the state root stops every tenant; one in a tenant directory
    stops that tenant. Only the operator CLI writes these files. No MCP tool can clear them.
    """

    def __init__(self, paths: TenantPaths):
        self.paths = paths

    def _files(self) -> list[Path]:
        return [self.paths.root / HALT_FILE, self.paths.dir / HALT_FILE]

    def status(self) -> dict | None:
        for path in self._files():
            if path.exists():
                try:
                    info = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    info = {"reason": "unreadable_halt_file"}
                info["scope"] = "global" if path.parent == self.paths.root else "tenant"
                return info
        return None

    def halted(self) -> bool:
        # Any halt file, readable or not, halts: fail closed.
        return any(path.exists() for path in self._files())

    @staticmethod
    def engage(target_dir: Path, *, operator: str, reason: str) -> Path:
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / HALT_FILE
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({
                "operator": operator,
                "reason": reason,
                "halted_at": datetime.now(timezone.utc).isoformat(),
            }, handle, sort_keys=True)
        os.replace(tmp, path)
        return path

    @staticmethod
    def release(target_dir: Path) -> bool:
        path = target_dir / HALT_FILE
        if path.exists():
            path.unlink()
            return True
        return False
