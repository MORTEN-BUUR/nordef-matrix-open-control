# Deployment

The control plane is CPU-only: deterministic rules + Ed25519, no inference, **no GPU**.
1 vCPU and 512 MB RAM serve many agents.

## Role separation (do this first)

| Role | Where | Holds |
|---|---|---|
| Human approver | own laptop / YubiKey-backed workstation | mandate **private** key (`nordef-root keygen`) |
| Vendor (NORDEF) | offline signing machine | license **private** key (`nordef-root issue-license`) |
| Server | LXC / container | public keys only, license token, evidence |
| Agent | separate VM/container | SSH client key for `nordef-client`, nothing else |

Never put a private signing key on the server or in an agent's reach.

```bash
# On the approver's machine
nordef-root keygen --key-id ops-lead-2026 --out ~/.nordef/ops-lead.pem
# → ~/.nordef/ops-lead.pub.json  (copy to server as /etc/nordef/trusted-keys.json)
```

## Proxmox VE 9.x (recommended)

```bash
# On the PVE node, from a checkout of this repository
./deploy/proxmox/create-lxc.sh 950 vmbr0 local-lvm
pct push 950 trusted-keys.json /etc/nordef/trusted-keys.json
pct push 950 license.key       /etc/nordef/license.key
pct push 950 license-keys.json /etc/nordef/license-keys.json
pct exec 950 -- nordef-add-client "$(cat agent-vm.pub)"
pct exec 950 -- sh -c 'nordef-admin fingerprint'   # pin in /etc/nordef/nordef.env
```

What you get:

- unprivileged Debian 13 LXC, `protection=1`, Proxmox firewall `DROP` in/out except SSH in;
- `nordef-mcp.socket` → one sandboxed `nordef-mcp@` process per connection
  (`PrivateNetwork`, `ProtectSystem=strict`, empty capability set, `MemoryMax=256M`);
- SSH key-only; `nordef-client` is forced into the MCP socket (no shell, no forwarding);
- evidence in `/var/lib/nordef` owned by `nordef`, mode 0700.

Recommended extras:

- back up `/var/lib/nordef` to **Proxmox Backup Server** daily and keep backups ≥ 6 months
  (EU AI Act art. 26(6));
- put agent VMs on their own bridge/VLAN with `policy_out: DROP` and allow only the model
  endpoint and `nordef-control:22`;
- one container per customer environment (= one license / one pricing "environment").

## Docker

```bash
mkdir -p deploy/config && cp trusted-keys.json license.key license-keys.json deploy/config/
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml run --rm -T nordef-mcp   # MCP stdio
```

The compose file runs with `network_mode: none`, read-only rootfs, `cap_drop: ALL`,
`no-new-privileges` and UID 10001. Build status in this release: **PENDING** (not built in CI;
no Docker daemon was available where it was written).

## Norsk driftsguide (kort)

**Stoppknapp (art. 14):** `nordef-ops halt --operator "<navn>" --reason "<hvorfor>"`
stopper alle agenter umiddelbart (alle verktøy som tar beslutninger svarer kode 2).
Overvåking og rapport virker fortsatt. Gjenoppta med
`nordef-ops resume --operator "<navn>"`. Begge hendelser logges i beviskjeden.
Bare for én kunde: legg til `--tenant <navn>`.

**Godkjenne en handling:** Agenten får kode 1. Godkjenneren kjører på sin egen maskin:

```bash
nordef-root sign-mandate --key ~/.nordef/ops-lead.pem --key-id ops-lead-2026 \
  --subject "Kari Nordmann, driftsleder" --action restart_vm --target vm-101 \
  --scope write:proxmox --side-effects --ttl 300
```

Tokenet gjelder bare denne ene handlingen, i maks 15 minutter, og kun én gang.

**Revisjonsrapport (art. 26):** `nordef-ops report --tenant default > rapport.md`
viser om kjeden er gyldig, hvem som godkjente hva, stopp-historikk og loggperiode
(≥ 183 dager kreves).

**Kontroll av kjeden:** `nordef-ops verify` — returnerer feil om noe er endret.
