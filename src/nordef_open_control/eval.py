from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .control import ControlPlane
from .models import ActionRequest, InputEnvelope, SharedChannelObservation


def run_eval_bank(bank_path: str | Path, state_dir: str | Path) -> dict[str, Any]:
    bank_path = Path(bank_path)
    rows: list[dict[str, Any]] = []
    ids: set[str] = set()
    counts = {"0": 0, "1": 0, "2": 0}
    executed = 0
    control = ControlPlane(state_dir=state_dir)

    for line_number, line in enumerate(bank_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid eval JSON at line {line_number}") from exc
        case_id = str(case.get("id") or "")
        if not case_id:
            raise ValueError(f"missing eval id at line {line_number}")
        if case_id in ids:
            raise ValueError(f"duplicate eval id: {case_id}")
        ids.add(case_id)

        envelope = InputEnvelope(**case["input"])
        request = ActionRequest(**case["action"])
        channel_data = case.get("channel")
        if channel_data:
            channel_data = dict(channel_data)
            channel_data["writable_by_agents"] = tuple(channel_data.get("writable_by_agents") or ())
            channel = SharedChannelObservation(**channel_data)
        else:
            channel = None
        decision = control.evaluate(envelope, request, channel=channel)
        expected = int(case["expected_code"])
        passed = decision.code == expected and decision.execute is False
        counts[str(decision.code)] = counts.get(str(decision.code), 0) + 1
        executed += int(decision.execute)
        rows.append({
            "id": case_id,
            "expected_code": expected,
            "actual_code": decision.code,
            "state": decision.state,
            "execute": decision.execute,
            "passed": passed,
        })

    return {
        "total": len(rows),
        "failures": sum(not row["passed"] for row in rows),
        "executed": executed,
        "counts": counts,
        "rows": rows,
    }
