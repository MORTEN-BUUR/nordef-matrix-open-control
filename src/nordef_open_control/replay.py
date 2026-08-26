from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


class ReplayRegistryError(RuntimeError):
    pass


class FileReplayRegistry:
    """Persistent one-time nonce registry. Malformed state fails closed."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    @staticmethod
    def nonce_hash(nonce: str) -> str:
        return hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ReplayRegistryError("invalid replay registry") from exc
        if not isinstance(value, dict) or not isinstance(value.get("used_nonce_hashes"), list):
            raise ReplayRegistryError("invalid replay registry shape")
        hashes = value["used_nonce_hashes"]
        if not all(isinstance(x, str) and len(x) == 64 for x in hashes):
            raise ReplayRegistryError("invalid replay registry entries")
        return set(hashes)

    def is_used(self, nonce: str) -> bool:
        return self.nonce_hash(nonce) in self._load()

    def consume(self, nonce: str) -> bool:
        used = self._load()
        digest = self.nonce_hash(nonce)
        if digest in used:
            return False
        used.add(digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"used_nonce_hashes": sorted(used)}, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return True
