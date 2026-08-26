#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from nordef_open_control.eval import run_eval_bank


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NORDEF Matrix Open Control eval bank")
    parser.add_argument("--bank", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = run_eval_bank(args.bank, args.state_dir)
    payload = {"status": "PASS" if result["failures"] == 0 else "FAIL", **result}
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
