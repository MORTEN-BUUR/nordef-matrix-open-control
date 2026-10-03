from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path

from nordef_open_control import EvidenceChain
from nordef_open_control.integrity import PolicyIntegrityGuard, policy_fingerprint
from nordef_open_control.replay import FileReplayRegistry
from nordef_open_control.sandbox import SandboxError, check_runtime


def _append_many(path: str, worker: int, count: int) -> None:
    chain = EvidenceChain(path)
    for i in range(count):
        chain.append(event_id=f"{worker}-{i}", source="w", category="c", code=0, decision="d",
                     input_bytes=b"x", action_taken=False, metadata={})


def _consume(path: str, nonce: str, queue) -> None:
    queue.put(FileReplayRegistry(path).consume(nonce))


class ConcurrencyTests(unittest.TestCase):
    def test_parallel_processes_keep_chain_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "evidence.jsonl")
            procs = [multiprocessing.Process(target=_append_many, args=(path, w, 25)) for w in range(4)]
            for p in procs:
                p.start()
            for p in procs:
                p.join()
            result = EvidenceChain(path).verify()
            self.assertTrue(result.valid, result.reason)
            self.assertEqual(result.records, 100)

    def test_nonce_consumed_exactly_once_across_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "replay.json")
            queue = multiprocessing.Queue()
            procs = [multiprocessing.Process(target=_consume, args=(path, "nonce-abcdefghijkl", queue))
                     for _ in range(6)]
            for p in procs:
                p.start()
            for p in procs:
                p.join()
            results = [queue.get() for _ in procs]
            self.assertEqual(results.count(True), 1)


class EvidenceIncrementalTests(unittest.TestCase):
    def test_append_refuses_after_truncation_or_tail_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.jsonl"
            chain = EvidenceChain(path)
            for i in range(3):
                _append_many(str(path), i, 1)
            chain.append(event_id="x", source="s", category="c", code=0, decision="d",
                         input_bytes=b"x", action_taken=False, metadata={})
            lines = path.read_text().splitlines()
            # Append a forged record from outside the chain object.
            forged = json.loads(lines[-1])
            forged["decision"] = "forged"
            path.write_text("\n".join(lines + [json.dumps(forged)]) + "\n")
            with self.assertRaises(RuntimeError):
                chain.append(event_id="y", source="s", category="c", code=0, decision="d",
                             input_bytes=b"x", action_taken=False, metadata={})
            # Truncation (dropping the forged and last record) is detected by full re-verify.
            path.write_text("\n".join(lines[1:]) + "\n")
            with self.assertRaises(RuntimeError):
                chain.append(event_id="z", source="s", category="c", code=0, decision="d",
                             input_bytes=b"x", action_taken=False, metadata={})


class IntegrityTests(unittest.TestCase):
    def test_pinned_fingerprint(self):
        self.assertTrue(PolicyIntegrityGuard(policy_fingerprint()).check())
        self.assertFalse(PolicyIntegrityGuard("0" * 64).check())


class SandboxTests(unittest.TestCase):
    def test_root_refused_unless_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SandboxError):
                check_runtime(tmp, euid=0)

    def test_foreign_owner_and_world_writable_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            uid = os.geteuid()
            with self.assertRaises(SandboxError):
                check_runtime(tmp, allow_root=True, euid=uid + 12345)
            os.chmod(tmp, 0o777)
            with self.assertRaises(SandboxError):
                check_runtime(tmp, allow_root=True, euid=uid)
            os.chmod(tmp, 0o700)
            check_runtime(tmp, allow_root=True, euid=uid)


if __name__ == "__main__":
    unittest.main()
