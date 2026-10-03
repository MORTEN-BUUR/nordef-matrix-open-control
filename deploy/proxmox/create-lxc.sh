#!/usr/bin/env bash
# Run on a Proxmox VE 9.x node as root. Creates an unprivileged Debian 13 container for
# NORDEF Open Control and installs the service inside it. No GPU, 1 vCPU, 512 MB RAM.
#
#   ./create-lxc.sh <ctid> <bridge> [storage]
#   ./create-lxc.sh 950 vmbr0 local-lvm
set -euo pipefail

CTID="${1:?usage: create-lxc.sh <ctid> <bridge> [storage]}"
BRIDGE="${2:?bridge, e.g. vmbr0}"
STORAGE="${3:-local-lvm}"
HOSTNAME="${NORDEF_HOSTNAME:-nordef-control}"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

command -v pct >/dev/null || { echo "pct not found: run this on a Proxmox VE node" >&2; exit 1; }

pveam update >/dev/null
TEMPLATE="$(pveam available --section system | awk '/debian-13-standard/ {print $2}' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || { echo "no debian-13-standard template available" >&2; exit 1; }
pveam list local | grep -q "$TEMPLATE" || pveam download local "$TEMPLATE"

pct create "$CTID" "local:vztmpl/$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --unprivileged 1 \
  --features nesting=1,keyctl=0 \
  --cores 1 --memory 512 --swap 256 \
  --rootfs "$STORAGE:4" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp,firewall=1" \
  --onboot 1 \
  --protection 1

# Proxmox firewall: deny by default, allow only SSH in (MCP travels over SSH).
mkdir -p /etc/pve/firewall
cat > "/etc/pve/firewall/$CTID.fw" <<EOF
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: DROP

[RULES]
IN SSH(ACCEPT) -log nolog
OUT DNS(ACCEPT) -log nolog
OUT HTTP(ACCEPT) -log nolog
OUT HTTPS(ACCEPT) -log nolog
EOF
# Outbound HTTP/HTTPS is only needed for apt/pip during install; remove those two lines
# afterwards (and reload with `pve-firewall compile`) to leave the container with no egress.

pct start "$CTID"
sleep 5
TAR="$(mktemp --suffix=.tar.gz)"
tar -C "$REPO_DIR" --exclude=.git --exclude=state -czf "$TAR" .
pct push "$CTID" "$TAR" /root/nordef-src.tar.gz
rm -f "$TAR"
pct exec "$CTID" -- bash -c 'mkdir -p /root/nordef-src && tar -C /root/nordef-src -xzf /root/nordef-src.tar.gz && /root/nordef-src/deploy/proxmox/install.sh'

echo
echo "Container $CTID ready. Next:"
echo "  1. Copy trusted-keys.json, license.key, license-keys.json into /etc/nordef/ (pct push)."
echo "  2. Add each MCP client's SSH public key:  pct exec $CTID -- nordef-add-client '<ssh-ed25519 ...>'"
echo "  3. Remove the outbound HTTP/HTTPS rules in /etc/pve/firewall/$CTID.fw."
