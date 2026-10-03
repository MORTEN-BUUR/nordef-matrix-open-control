# Security whitepaper — NORDEF Matrix Open Control 3.1.0-lab

## Principle

```text
model text != authority
root verified != action executed
log visible to agent != immutable evidence
```

A model may propose actions. A deterministic control plane outside the model decides, and only
a human holding a private key can authorize a side effect.

## Layers

1. **Input boundary.** Untrusted text matching instruction-injection rules is blocked (code 2)
   before it reaches the model transport. Trust is set by the operator per source name; it is
   never a tool argument.
2. **Action policy.** Known-dangerous actions are always blocked. Side effects and unknown
   actions are held (code 1). Only listed read-only actions pass (code 0).
3. **Shared-channel boundary.** Storage writable by more than one agent is blocked as a covert
   coordination channel.
4. **Human mandate.** Ed25519 signature over subject, exact action/target/scope/side-effect
   flag, canonical request hash, issue/expiry (TTL ≤ 900 s, 30 s skew), one-time nonce and key
   id. Test-only keys are rejected.
5. **Replay protection.** Nonce hashes are persisted under an exclusive file lock; exactly one
   consumer can win, across processes.
6. **Evidence chain.** Append-only JSONL; each record carries the SHA-256 of the previous one.
   Raw input is stored only as a hash; metadata is allow-listed (agent, tenant, subject, key id,
   request hash, mandate hash). Appends verify new records incrementally and re-verify fully
   after truncation; `nordef-admin verify` checks the whole chain.
7. **Stop button.** A `HALT.json` file (global or per tenant), written only by the operator
   CLI, makes every decision tool return code 2. Halt and resume are themselves evidence.
8. **Policy integrity.** The policy tables are fingerprinted; a mismatch with the pinned or
   startup value fails every tool closed.
9. **License.** Ed25519-signed `NORDEF1.<payload>.<sig>` tokens with tool scope, agent cap,
   monthly request cap and expiry. Test/dev licenses are rejected outside `--dev`.
10. **Runtime.** Refuses to run as root or with a state directory that is foreign-owned or
    group/world-writable. Packaged with systemd sandboxing / read-only container, no network.
11. **Tenant isolation.** Per-tenant directories derived from a validated operator-set id
    (`[a-z0-9-]`, no traversal); evidence, replay and halt state are never shared.

## Verified by tests

58 unit/integration tests, including: in-memory and real stdio MCP sessions, replay across 6
processes (exactly one winner), 4 concurrent writers keeping the chain valid, forged and
truncated evidence detected, policy monkey-patching failing closed, license tampering, scope,
agent and request caps, tenant isolation and traversal, stop button not consuming mandates.

## Residual risks (needs external controls)

- A root-level compromise of the host can rewrite code and evidence: ship evidence to storage
  the server cannot modify (PBS with immutable backups, WORM bucket, or an external timestamping
  service for the chain head).
- In-place rewrite of old records without size change is caught by full `verify`, not by the
  incremental check on append: schedule `nordef-ops verify` (e.g. hourly systemd timer).
- Deterministic input rules do not detect every prompt injection; the action gate and human
  mandate are the real boundary.
- The executor that performs real actions is outside this product and must re-check the
  manifest's `request_hash`.
- Signing keys should be hardware-backed (YubiKey / smartcard via PKCS#11) — backlog.

## Backlog

- run-state pause/resume of an agent run tied to a pending mandate;
- pluggable guardrail interface (custom classifiers per tenant);
- output-side checks before results leave the agent;
- REST API and multi-tenant SaaS (phase 2), remote MCP over Streamable HTTP + OAuth (phase 3);
- signed chain-head checkpoints exported to an external timestamp authority.
