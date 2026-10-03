#!/usr/bin/env bash
# Run as root inside a Debian 13 container or VM. Idempotent.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/../.." && pwd)"
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q python3 python3-venv socat openssh-server

id nordef >/dev/null 2>&1 || useradd --system --home-dir /var/lib/nordef --shell /usr/sbin/nologin nordef
getent group nordef-clients >/dev/null || groupadd --system nordef-clients
id nordef-client >/dev/null 2>&1 || useradd --create-home --shell /bin/sh --groups nordef-clients nordef-client
passwd -l nordef-client >/dev/null

install -d -m 0700 -o nordef -g nordef /var/lib/nordef
install -d -m 0750 -o root -g nordef /etc/nordef
python3 -m venv /opt/nordef/venv
/opt/nordef/venv/bin/pip install --quiet --upgrade pip
/opt/nordef/venv/bin/pip install --quiet "$SRC"
for tool in nordef-admin nordef-root; do
  ln -sf "/opt/nordef/venv/bin/$tool" "/usr/local/bin/$tool"
done

[ -f /etc/nordef/nordef.env ] || install -m 0640 -o root -g nordef \
  "$SRC/deploy/proxmox/nordef.env.example" /etc/nordef/nordef.env
install -m 0644 "$SRC/deploy/proxmox/nordef-mcp.socket" /etc/systemd/system/nordef-mcp.socket
install -m 0644 "$SRC/deploy/proxmox/nordef-mcp@.service" /etc/systemd/system/nordef-mcp@.service
install -m 0755 "$SRC/deploy/proxmox/nordef-add-client" /usr/local/sbin/nordef-add-client

# Operator tools must write as the service user so evidence stays owned by nordef.
cat > /usr/local/sbin/nordef-ops <<'EOF'
#!/bin/sh
set -a; . /etc/nordef/nordef.env; set +a
exec runuser -u nordef -- /opt/nordef/venv/bin/nordef-admin "$@"
EOF
chmod 0755 /usr/local/sbin/nordef-ops

# SSH: keys only, no forwarding, the client account can only reach the MCP socket.
cat > /etc/ssh/sshd_config.d/nordef.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
Match User nordef-client
    ForceCommand /usr/bin/socat - UNIX-CONNECT:/run/nordef/mcp.sock
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTTY no
EOF

systemctl daemon-reload
systemctl enable --now nordef-mcp.socket
systemctl restart ssh

echo "Installed. Policy fingerprint to pin in /etc/nordef/nordef.env:"
/opt/nordef/venv/bin/nordef-admin fingerprint
echo "Stop button:   nordef-ops halt --operator <name> --reason <why>"
echo "Audit report:  nordef-ops report --tenant default"
