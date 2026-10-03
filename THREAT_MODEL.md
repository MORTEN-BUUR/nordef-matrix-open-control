# Threat Model

## Protected assets

- human/root authority;
- action scope and target integrity;
- model/tool transport boundary;
- secrets and private input;
- evidence integrity;
- network and system side effects;
- separation between concurrent agents.

## Threats covered by this LAB

| Threat | Control | Status |
|---|---|---|
| Untrusted text attempts to become instructions | deterministic pre-model boundary | covered by measured rules |
| False root language in prompts | Ed25519 mandate outside model text | covered |
| Action/target/scope substitution | canonical request hash + exact matching | covered |
| Expired or overlong approval | timestamp and TTL gate | covered |
| Replayed approval | persistent hashed nonce registry | covered |
| Test key/attestation used as authority | `test_only` rejection | covered |
| Shared service used as agent message board | multi-writer channel policy | covered at declared metadata layer |
| Raw secrets copied into evidence | input hashing + metadata allowlist | covered by tests |
| Evidence record modified afterward | previous-hash chain verification | covered by tests |
| Model initiates a live action | no executor; `execute=false` invariant | covered in LAB |
| Model claims its input is trusted via MCP | trust set by operator per source, not a tool argument | covered by tests |
| Model releases the stop button or signs its own mandate | no MCP tool can; operator CLI / offline key only | covered by tests |
| Concurrent agents race the replay registry or evidence chain | exclusive file locks | covered by tests |
| Policy tables altered at runtime | fingerprint guard, fail closed | covered by tests |
| Cross-tenant leakage or path traversal | validated tenant id, separate state dirs | covered by tests |
| Unlicensed or over-limit use | Ed25519 license, scope and caps | covered by tests |

## Threats requiring external enforcement

This library cannot, by itself, prevent:

- kernel, hypervisor, container, package-manager, or supply-chain escapes;
- hidden network egress through a service that is incorrectly allowlisted;
- credential exposure elsewhere on the internet;
- a compromised host rewriting both code and evidence;
- malicious or compromised human signing keys;
- collusion through channels not described to the control plane;
- unknown semantic attacks outside deterministic rules;
- live connector abuse after an integrator adds an executor.

Production use therefore requires independent controls:

1. per-agent identity and isolated writable namespaces;
2. network deny-by-default enforced outside the workload;
3. dependency proxies that cannot make arbitrary outbound requests;
4. evidence storage the agent cannot modify;
5. hardware-backed or otherwise strongly protected human signing keys;
6. independent executor re-verification of the same mandate;
7. resource limits, kill switch, rollback, and incident response;
8. recurring adversarial evaluation and human review.

## Security invariants

```text
model text != authority
root verified != action executed
action attempted != postcondition verified
shared convenience service != trusted boundary
log visible to agent != immutable evidence
```

## Incident-pattern mapping

The included eval bank maps to public lessons from the 2026 OpenAI–Hugging Face incident: reward hacking, false authority, shared message boards, cross-agent coordination, unauthorized side effects, credential exfiltration, and arbitrary command execution requests.

The bank is a small deterministic regression set. Passing it does not prove coverage of the full incident or unknown future behavior.
