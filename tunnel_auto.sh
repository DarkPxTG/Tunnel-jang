#!/usr/bin/env bash
set -Eeuo pipefail

# One-run two-server Xray tunnel bootstrap.
# Run as root on either endpoint. It asks only for the OTHER server's IP,
# SSH username and SSH password, then uses GeoIP to infer each endpoint's role.
# GeoIP can be inaccurate; review the detected roles before accepting.

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

command -v curl >/dev/null 2>&1 || { apt-get update && apt-get install -y curl; }
command -v python3 >/dev/null 2>&1 || { apt-get update && apt-get install -y python3; }

read -r -p "IP/domain of the OTHER server: " REMOTE_HOST
read -r -p "SSH username on the OTHER server (e.g. root): " REMOTE_USER
read -r -s -p "SSH password for the OTHER server: " REMOTE_PASS
echo

[[ "$REMOTE_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Invalid host."; exit 1; }
[[ -n "$REMOTE_USER" && -n "$REMOTE_PASS" ]] || { echo "Username/password cannot be empty."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openssh-client sshpass curl ca-certificates python3

get_country() {
  local host="$1" result
  result="$(curl -fsS --max-time 8 "https://ipapi.co/${host}/country/" 2>/dev/null || true)"
  printf '%s' "$result" | tr -d '[:space:]'
}
get_public_ip() {
  curl -fsS --max-time 8 https://api.ipify.org
}

LOCAL_IP="$(get_public_ip)" || { echo "Could not detect this server's public IP."; exit 1; }
REMOTE_IP="$REMOTE_HOST"
LOCAL_COUNTRY="$(get_country "$LOCAL_IP")"
REMOTE_COUNTRY="$(get_country "$REMOTE_HOST")"

echo
echo "Detected this server: $LOCAL_IP (country: ${LOCAL_COUNTRY:-unknown})"
echo "Detected other server: $REMOTE_HOST (country: ${REMOTE_COUNTRY:-unknown})"
echo "Role detection uses IP geolocation and may be wrong."

# Iran is inferred from country code IR. If either result is ambiguous, stop rather
# than silently building the tunnel in the wrong direction.
if [[ "$LOCAL_COUNTRY" == "IR" && "$REMOTE_COUNTRY" != "IR" && -n "$REMOTE_COUNTRY" ]]; then
  LOCAL_ROLE="iran"; REMOTE_ROLE="abroad"
elif [[ "$REMOTE_COUNTRY" == "IR" && "$LOCAL_COUNTRY" != "IR" && -n "$LOCAL_COUNTRY" ]]; then
  LOCAL_ROLE="abroad"; REMOTE_ROLE="iran"
else
  echo "Cannot safely infer which server is in Iran from GeoIP."
  echo "No changes have been made. Check that both public IPs are correct and GeoIP works."
  exit 1
fi

echo "Role decision: this server=$LOCAL_ROLE; other server=$REMOTE_ROLE"
read -r -p "Proceed with this role decision? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }

# Generate UUIDs on this endpoint; same values are installed on both servers.
IRAN_UUID="$(cat /proc/sys/kernel/random/uuid)"
ABROAD_UUID="$(cat /proc/sys/kernel/random/uuid)"
IRAN_IP="$LOCAL_IP"; ABROAD_IP="$REMOTE_HOST"
if [[ "$LOCAL_ROLE" == "abroad" ]]; then IRAN_IP="$REMOTE_HOST"; ABROAD_IP="$LOCAL_IP"; fi

REMOTE_SCRIPT="$(cat <<'REMOTE_EOF'
set -Eeuo pipefail
ROLE="$1"
IRAN_IP="$2"
ABROAD_IP="$3"
IRAN_UUID="$4"
ABROAD_UUID="$5"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi
CONFIG=/usr/local/etc/xray/config.json
mkdir -p /usr/local/etc/xray
if [[ -f "$CONFIG" ]]; then cp -a "$CONFIG" "$CONFIG.backup.$(date +%Y%m%d%H%M%S)"; fi
if [[ "$ROLE" == "abroad" ]]; then
cat > "$CONFIG" <<JSON
{
 "log":{"loglevel":"warning"},
 "inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless",
  "settings":{"clients":[{"id":"$ABROAD_UUID"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "outbounds":[{"protocol":"freedom"}]
}
JSON
else
cat > "$CONFIG" <<JSON
{
 "log":{"loglevel":"warning"},
 "inbounds":[{"tag":"vless-in","listen":"0.0.0.0","port":443,"protocol":"vless",
  "settings":{"clients":[{"id":"$IRAN_UUID"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "outbounds":[{"tag":"to-abroad","protocol":"vless",
  "settings":{"vnext":[{"address":"$ABROAD_IP","port":443,
   "users":[{"id":"$ABROAD_UUID","encryption":"none"}]}]},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "routing":{"rules":[{"type":"field","inboundTag":["vless-in"],"outboundTag":"to-abroad"}]}
}
JSON
fi
xray run -test -config "$CONFIG"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow 443/tcp; fi
systemctl enable xray
systemctl restart xray
sleep 1
systemctl is-active --quiet xray || { journalctl -u xray -n 50 --no-pager; exit 1; }
echo "REMOTE_XRAY_OK"
REMOTE_EOF
)"

# Configure the remote endpoint via SSH. Password authentication must be enabled on it.
export SSHPASS="$REMOTE_PASS"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=15)
if ! sshpass -e ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" 'bash -s' -- "$REMOTE_ROLE" "$IRAN_IP" "$ABROAD_IP" "$IRAN_UUID" "$ABROAD_UUID" <<< "$REMOTE_SCRIPT"; then
  unset SSHPASS REMOTE_PASS
  echo
  echo "Remote setup failed. Common causes: password SSH login disabled, wrong username/password,"
  echo "root login disabled, or port 22 blocked. No guarantee of a working tunnel."
  exit 1
fi

# Configure this endpoint with the same values.
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi
CONFIG=/usr/local/etc/xray/config.json
mkdir -p /usr/local/etc/xray
if [[ -f "$CONFIG" ]]; then cp -a "$CONFIG" "$CONFIG.backup.$(date +%Y%m%d%H%M%S)"; fi
if [[ "$LOCAL_ROLE" == "abroad" ]]; then
cat > "$CONFIG" <<JSON
{
 "log":{"loglevel":"warning"},
 "inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless",
  "settings":{"clients":[{"id":"$ABROAD_UUID"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "outbounds":[{"protocol":"freedom"}]
}
JSON
else
cat > "$CONFIG" <<JSON
{
 "log":{"loglevel":"warning"},
 "inbounds":[{"tag":"vless-in","listen":"0.0.0.0","port":443,"protocol":"vless",
  "settings":{"clients":[{"id":"$IRAN_UUID"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "outbounds":[{"tag":"to-abroad","protocol":"vless",
  "settings":{"vnext":[{"address":"$ABROAD_IP","port":443,
   "users":[{"id":"$ABROAD_UUID","encryption":"none"}]}]},
  "streamSettings":{"network":"tcp","security":"none"}}],
 "routing":{"rules":[{"type":"field","inboundTag":["vless-in"],"outboundTag":"to-abroad"}]}
}
JSON
fi

xray run -test -config "$CONFIG"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow 443/tcp; fi
systemctl enable xray
systemctl restart xray
sleep 1
if ! systemctl is-active --quiet xray; then
  journalctl -u xray -n 50 --no-pager
  unset SSHPASS REMOTE_PASS
  exit 1
fi

unset SSHPASS REMOTE_PASS
echo
echo "=== Xray services are running on both servers ==="
echo "Iran endpoint: $IRAN_IP:443"
echo "Abroad endpoint: $ABROAD_IP:443"
if [[ "$LOCAL_ROLE" == "iran" ]]; then
  echo "Client link (VLESS/TCP, security=none):"
  echo "vless://${IRAN_UUID}@${IRAN_IP}:443?type=tcp&encryption=none&security=none#Iran-Tunnel"
else
  echo "Client link (VLESS/TCP, security=none):"
  echo "vless://${IRAN_UUID}@${IRAN_IP}:443?type=tcp&encryption=none&security=none#Iran-Tunnel"
fi
echo
echo "Keep the client link private. This configuration has NO TLS encryption."
echo "If port 443 is already used by another service or blocked by the provider firewall, setup may fail."
