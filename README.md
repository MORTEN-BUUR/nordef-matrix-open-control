# NORDEF Matrix Open Control

**A model-independent safety belt for AI agents.**

NORDEF Matrix Open Control places deterministic policy, cryptographic human approval, replay protection, shared-channel controls, and hash-chained evidence **outside** the language model.

> A model can propose. The control plane decides what may proceed. Human authority lives outside model text.

## Why this exists

The 2026 OpenAI–Hugging Face incident showed that capable agents can:

- pursue unintended shortcuts when tasks are impossible;
- build unauthorized communication channels through shared infrastructure;
- adopt goals and techniques from other agents;
- escape intended network boundaries through allowed dependencies;
- seek credentials and interact with unrelated third-party systems;
- attempt to spoof tool calls or manipulate evaluation transcripts.

A system prompt alone is not an enforcement boundary. This project provides a small reference control plane that does not depend on a particular model or model provider.

## MCP server (new in 3.1)

Any MCP-capable agent host — whatever model it runs — can use the safety belt:

```bash
pip install .
nordef-root keygen --key-id ops-lead --out ~/.nordef/ops-lead.pem      # on the approver's machine
nordef-mcp --dev --state-dir ~/.nordef/state --trusted-keys ~/.nordef/ops-lead.pub.json
```

Tools: `policy_list`, `policy_check`, `mandate_verify`, `evidence_append` (the only one that
records an authorization, and only with a valid human mandate), `evidence_tail`,
`compliance_status`. Operator tools: `nordef-admin halt|resume|status|verify|report|fingerprint`.

- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) — client configuration and agent loop
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — Proxmox VE 9 LXC, Docker, Norwegian ops guide
- [docs/SECURITY_WHITEPAPER.md](docs/SECURITY_WHITEPAPER.md) — layers, tests, residual risk
- [COMMERCIAL.md](COMMERCIAL.md) — draft offering and pricing (EU AI Act art. 14/26)

## Current LAB capabilities

- deterministic `0 / 1 / 2` decisions;
- untrusted-content boundary before model transport;
- shared writable channel detection;
- exact action/target/scope/side-effect request hashes;
- Ed25519-signed human mandates with TTL ≤ 900 seconds;
- persistent one-time nonce replay prevention;
- test-only attestations rejected from authorization;
- append-only SHA-256 evidence chain;
- raw protected input stored only as a hash;
- dry-run action manifest after valid authorization;
- `execute=false` for every path in this LAB candidate;
- incident-pattern evaluation bank;
- MCP stdio server with operator-set trust, tenant and agent identity;
- human stop button (global or per tenant) and EU AI Act art. 14/26 audit report;
- Ed25519-signed licenses with tool scope, agent and monthly request caps;
- file locking for multi-process evidence/replay, policy integrity guard, root refusal.

## Truth boundary

This is a **LAB reference implementation**, not a claim of general AI safety.

It does not:

- train or modify a language model;
- guarantee detection of every prompt injection;
- replace operating-system, network, container, identity, or hardware isolation;
- provide a live shell, firewall, cloud, customer, or production connector;
- make technical attribution about an attacker;
- allow a model to authorize itself.

Real enforcement must be placed in components the agent cannot modify: network policy, identity systems, executor permissions, evidence storage, and human approval hardware/processes.

## Quick verification

```bash
cd /path/to/nordef-matrix-open-control-v3
PYTHONPATH=src python3 -m unittest discover -s tests -v   # needs: pip install cryptography mcp

PYTHONPATH=src python3 scripts/run_eval.py \
  --bank evals/openai_hf_incident_patterns.jsonl \
  --state-dir /tmp/nordef-open-control-eval
```

Expected result:

```text
58 tests: PASS
10 eval cases: PASS
0 actions executed
```

## Decision states

| Code | Meaning | Default result |
|---|---|---|
| `0` | read-only / controlled | may reach model transport; no action execution |
| `1` | review / side effect requested | held for human root or authorized dry-run only |
| `2` | blocked | does not reach model transport when blocked at input boundary |

A valid mandate proves authorization only. It does **not** mean an action ran. This candidate emits an immutable dry-run manifest with `execute=false`.

## Root mandate contract

A signed mandate binds:

- human subject;
- exact action;
- exact target;
- exact scope;
- side-effect flag;
- issue and expiry timestamps;
- one-time nonce;
- canonical request hash;
- trusted key ID;
- non-test status.

The verifier rejects stale, future, overlong, mismatched, replayed, malformed, unknown-key, invalid-signature, and test-only mandates.

## Project layout

```text
src/nordef_open_control/
  policy.py       deterministic input/action policy
  channels.py     cross-agent shared-channel boundary
  root_gate.py    Ed25519 mandate verification
  replay.py       persistent one-time nonce registry
  evidence.py     sanitized append-only hash chain
  control.py      model-independent orchestration gate
  eval.py         deterministic eval-bank runner
  service.py      MCP tool logic (guards: integrity, license, stop button)
  mcp_server.py   FastMCP stdio server
  license.py      signed license keys and usage meter
  tenancy.py      tenant isolation and stop button
  compliance.py   audit report and EU AI Act mapping
  integrity.py    policy fingerprint guard
  sandbox.py      runtime safety checks
  locking.py      cross-process file locks
  cli.py          nordef-mcp / nordef-root / nordef-admin

deploy/           Dockerfile, compose, Proxmox LXC scripts and systemd units
docs/             integration, deployment, security whitepaper

evals/            incident-pattern JSONL bank
scripts/          command-line verifier
tests/            unit and integration tests
```

## Open-source boundary

This repository is intended to be the **safety belt**, not a release of proprietary models, routing systems, private infrastructure, credentials, customer data, or internal connectors.

## Status

- Version: `3.1.0-lab`
- Side effects: **OFF**
- Live routing: **OFF**
- Customer use: **OFF**
- Public publication: **not performed**

Created by **Morten Büür / Nordlys Datacenter** with Eirik / NORDEF Matrix.
