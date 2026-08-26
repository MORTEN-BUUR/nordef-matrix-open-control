from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ALLOWED_METADATA = {
    "rule_ids", "safe_label", "reason_code", "connector", "result_state", "source_count"
}


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metadata.items() if key in _ALLOWED_METADATA}


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    reason: str
    records: int = 0


class EvidenceChain:
    """Append-only local hash chain containing hashes, never raw protected input."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    @staticmethod
    def _record_hash(record_without_hash: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(record_without_hash)).hexdigest()

    def _records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records

    def verify(self) -> ChainVerification:
        try:
            records = self._records()
        except Exception:
            return ChainVerification(False, "invalid_json", 0)
        previous = None
        for index, record in enumerate(records):
            if record.get("previous_hash") != previous:
                return ChainVerification(False, "previous_hash_mismatch", index)
            stored = record.get("record_hash")
            body = dict(record)
            body.pop("record_hash", None)
            if stored != self._record_hash(body):
                return ChainVerification(False, "record_hash_mismatch", index)
            previous = stored
        return ChainVerification(True, "verified", len(records))

    def append(
        self,
        *,
        event_id: str,
        source: str,
        category: str,
        code: int,
        decision: str,
        input_bytes: bytes,
        action_taken: bool,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        verification = self.verify()
        if not verification.valid:
            raise RuntimeError(f"evidence chain invalid: {verification.reason}")
        records = self._records()
        previous = records[-1]["record_hash"] if records else None
        body = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "category": category,
            "code": int(code),
            "decision": decision,
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "previous_hash": previous,
            "action_taken": bool(action_taken),
            "metadata": _safe_metadata(metadata),
        }
        record = dict(body)
        record["record_hash"] = self._record_hash(body)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record
