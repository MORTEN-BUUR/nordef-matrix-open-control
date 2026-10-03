# Commercial offering — DRAFT

Status: internal draft. Prices, license terms and competitor figures below are **not final and
not verified**. No legal conclusion is made here.

## What is sold

Not "AI security" in the abstract, but **evidence of human oversight**: a compliance owner can
show an auditor that no AI agent performed a side effect without a named human approving that
exact action, that a human could stop the system at any time, and that the log proving it has
not been altered.

| Customer need | Product feature |
|---|---|
| EU AI Act art. 14 — monitor, understand, override, stop | 0/1/2 policy, signed mandates, `nordef-ops halt` |
| EU AI Act art. 26 — competent overseers, logs ≥ 6 months, incident follow-up | subject + key id per approval, hash-chained evidence, audit report |
| Works with any model and agent framework | MCP stdio server; no model calls |
| Data stays in Norway/EU | self-hosted on the customer's or Nordlys' Proxmox; no cloud dependency |

Whether a given customer system is high-risk, and which obligations apply, must be assessed by
the customer's counsel.

## Pricing structure (draft for discussion)

1. **Platform, per agent environment** — ~14 900–24 900 NOK/month. One environment = one
   license = one tenant/LXC with any number of models behind it (agent cap per license).
2. **Usage, per human-authorized side effect** — first 5 000–10 000/month included, then
   ~0.25–0.50 NOK each. Only code-1 actions that end in `authorized_dry_run` count
   (metered as `authorized_actions` in `license-usage.json`); reads (0) and blocks (2) are free.
3. **Audit package** — +50–100 % of platform: independent chain verification, quarterly
   compliance report, signed statement for the auditor.

Example: 50 000 authorized actions/month, 10 000 included → 14 900 + 40 000 × 0.30 ≈
**26 900 NOK/month** platform + usage (≈ 40 000+ NOK with the audit package).

Pilot: first three customers, 30 days free, ending with a real evidence report.

### Technical answer to "what is an environment?"

One server process serves one tenant and one agent identity per connection; one installation
can host many tenants (`/var/lib/nordef/tenants/<id>`), each with separate evidence, replay and
stop button. License limits (`max_agents`, monthly `max_requests`, tool scope) are enforced per
`license_id`. Recommended: one LXC per customer environment, so pricing, isolation and backup
follow the same boundary.

## License

`LICENSE` (MIT) is unchanged. A Business Source License 1.1 draft for the commercial edition is
in `LICENSE-BSL-1.1-DRAFT.md` and is **not in effect**.
