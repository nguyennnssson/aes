#!/usr/bin/env bash
# setup_ap.sh — Run once as root on the Raspberry Pi 4 (Bookworm).
# Configures AP+STA simultaneous mode: wlan0 stays connected to home WiFi,
# virtual ap0 becomes the access point for ESP32 devices on 192.168.4.0/24.
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

: "${AES_AP_PASSPHRASE:?Set AES_AP_PASSPHRASE (16-63 characters)}"
: "${AES_MQTT_MONITOR_PASSWORD:?Set AES_MQTT_MONITOR_PASSWORD}"
: "${AES_MQTT_RECEIVER_PASSWORD:?Set AES_MQTT_RECEIVER_PASSWORD}"
: "${AES_MQTT_DEVICE_CREDENTIALS_FILE:?Point to a root-readable device user:password file}"
: "${AES_DEVICE_LEASES_FILE:?Point to dnsmasq reservations (mac,ip,hostname)}"
: "${AES_MQTT_CA_CERT_SOURCE:?Point to the trusted gateway CA certificate}"
: "${AES_MQTT_SERVER_CERT_SOURCE:?Point to the gateway server certificate}"
: "${AES_MQTT_SERVER_KEY_SOURCE:?Point to the gateway server private key}"
AES_SERVICE_USER="${AES_SERVICE_USER:-pi}"

CREDENTIAL_RE='^[A-Za-z0-9._~!@#$%^&*+=?/-]+$'

if [ "${#AES_AP_PASSPHRASE}" -lt 16 ] || [ "${#AES_AP_PASSPHRASE}" -gt 63 ] \
        || ! [[ "$AES_AP_PASSPHRASE" =~ $CREDENTIAL_RE ]]; then
    echo "AES_AP_PASSPHRASE must be 16-63 shell-safe printable characters." >&2
    exit 1
fi
for credential_name in AES_MQTT_MONITOR_PASSWORD AES_MQTT_RECEIVER_PASSWORD; do
    credential_value="${!credential_name}"
    if [ "${#credential_value}" -lt 16 ] || [ "${#credential_value}" -gt 128 ] \
            || ! [[ "$credential_value" =~ $CREDENTIAL_RE ]]; then
        echo "$credential_name must be 16-128 shell-safe printable characters." >&2
        exit 1
    fi
done
if [ "$AES_MQTT_MONITOR_PASSWORD" = "$AES_MQTT_RECEIVER_PASSWORD" ]; then
    echo "Monitor and receiver must use distinct MQTT passwords." >&2
    exit 1
fi
if ! id "$AES_SERVICE_USER" >/dev/null 2>&1 \
        || ! [[ "$AES_SERVICE_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "AES_SERVICE_USER must identify an existing local service account." >&2
    exit 1
fi
for required_file in "$AES_MQTT_DEVICE_CREDENTIALS_FILE" "$AES_DEVICE_LEASES_FILE" "$AES_MQTT_CA_CERT_SOURCE" \
                     "$AES_MQTT_SERVER_CERT_SOURCE" "$AES_MQTT_SERVER_KEY_SOURCE"; do
    if [ ! -f "$required_file" ]; then
        echo "Required provisioning file does not exist: $required_file" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AES_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if ! [[ "$AES_REPO_ROOT" =~ ^/[A-Za-z0-9_./-]+$ ]]; then
    echo "Repository path contains unsupported characters: $AES_REPO_ROOT" >&2
    exit 1
fi
AES_SERVICE_GROUP="$(id -gn "$AES_SERVICE_USER")"

AP_IFACE="ap0"
AP_IP="192.168.4.1"
AP_NETMASK="255.255.255.0"
UPSTREAM_IFACE="wlan0"

echo "=== AES Gateway Setup ==="
echo "AP interface : $AP_IFACE ($AP_IP)"
echo "Upstream     : $UPSTREAM_IFACE"
echo ""

# ── 1. Install packages ───────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y hostapd dnsmasq mosquitto mosquitto-clients \
    python3-paho-mqtt iptables-persistent openssl rfkill

# ── 2. Unblock WiFi radio ─────────────────────────────────────────────────────
rfkill unblock wifi || true

# ── 3. Tell NetworkManager to leave ap0 alone ─────────────────────────────────
mkdir -p /etc/NetworkManager/conf.d/
cat > /etc/NetworkManager/conf.d/unmanaged-ap0.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:ap0
EOF
systemctl reload NetworkManager 2>/dev/null || true

# ── 4. Create virtual AP interface ───────────────────────────────────────────
if ! ip link show "$AP_IFACE" &>/dev/null; then
    iw dev "$UPSTREAM_IFACE" interface add "$AP_IFACE" type __ap
    echo "Created virtual interface $AP_IFACE"
else
    echo "$AP_IFACE already exists, skipping creation"
fi

# ── 5. Persist ap0 at boot ────────────────────────────────────────────────────
mkdir -p /etc/network/interfaces.d/
cat > /etc/network/interfaces.d/ap0 <<EOF
auto ap0
iface ap0 inet static
    address $AP_IP
    netmask $AP_NETMASK
    pre-up iw dev $UPSTREAM_IFACE interface add ap0 type __ap || true
EOF

# Bring up now
ip addr flush dev "$AP_IFACE" 2>/dev/null || true
ip addr add "$AP_IP/24" dev "$AP_IFACE" 2>/dev/null || true
ip link set "$AP_IFACE" up

# ── 6. Copy hostapd config ────────────────────────────────────────────────────
cp "$SCRIPT_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
escaped_ap_password=${AES_AP_PASSPHRASE//\\/\\\\}
escaped_ap_password=${escaped_ap_password//&/\\&}
escaped_ap_password=${escaped_ap_password//|/\\|}
sed -i "s|__SET_ON_PI__|$escaped_ap_password|" /etc/hostapd/hostapd.conf
if grep -q '__SET_ON_PI__' /etc/hostapd/hostapd.conf; then
    echo "Refusing to start hostapd with the placeholder passphrase." >&2
    exit 1
fi
chmod 600 /etc/hostapd/hostapd.conf
# Handle both `#DAEMON_CONF=` and `DAEMON_CONF=""` variants on Bookworm
sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# ── 7. Copy dnsmasq config ────────────────────────────────────────────────────
[ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
cp "$SCRIPT_DIR/dnsmasq.conf" /etc/dnsmasq.conf
install -d -m 755 /etc/dnsmasq.d
lease_config=$(mktemp /run/aes-dnsmasq-leases.XXXXXX)
lease_count=0
declare -A seen_lease_macs=()
declare -A seen_lease_ips=()
while IFS=, read -r lease_mac lease_ip lease_name; do
    if [ -z "$lease_mac$lease_ip$lease_name" ]; then
        continue
    fi
    if ! [[ "$lease_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] \
            || ! [[ "$lease_ip" =~ ^192\.168\.4\.([0-9]{1,3})$ ]] \
            || ! [[ "$lease_name" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,63}$ ]]; then
        echo "Invalid static lease entry: $lease_mac,$lease_ip,$lease_name" >&2
        rm -f "$lease_config"
        exit 1
    fi
    [[ "$lease_ip" =~ ^192\.168\.4\.([0-9]{1,3})$ ]]
    lease_octet="${BASH_REMATCH[1]}"
    if [ "$lease_octet" -lt 10 ] || [ "$lease_octet" -gt 50 ]; then
        echo "Static lease must stay within 192.168.4.10-50: $lease_ip" >&2
        rm -f "$lease_config"
        exit 1
    fi
    normalized_mac="${lease_mac,,}"
    if [[ -n "${seen_lease_macs[$normalized_mac]:-}" || -n "${seen_lease_ips[$lease_ip]:-}" ]]; then
        echo "Duplicate static lease MAC or IP: $lease_mac,$lease_ip" >&2
        rm -f "$lease_config"
        exit 1
    fi
    seen_lease_macs[$normalized_mac]=1
    seen_lease_ips[$lease_ip]=1
    printf 'dhcp-host=%s,%s,%s\n' "$lease_mac" "$lease_ip" "$lease_name" >> "$lease_config"
    lease_count=$((lease_count + 1))
done < "$AES_DEVICE_LEASES_FILE"
if [ "$lease_count" -eq 0 ]; then
    echo "AES_DEVICE_LEASES_FILE must contain at least one static device lease." >&2
    rm -f "$lease_config"
    exit 1
fi
install -m 644 -o root -g root "$lease_config" /etc/dnsmasq.d/aes-devices.conf
rm -f "$lease_config"

# ── 8. Copy mosquitto config ──────────────────────────────────────────────────
cp "$SCRIPT_DIR/mosquitto.conf" /etc/mosquitto/conf.d/aes.conf
install -d -m 750 -o mosquitto -g mosquitto /etc/mosquitto/certs
install -m 644 -o root -g mosquitto "$AES_MQTT_CA_CERT_SOURCE" /etc/mosquitto/certs/aes-ca.crt
install -m 644 -o root -g mosquitto "$AES_MQTT_SERVER_CERT_SOURCE" /etc/mosquitto/certs/aes-gateway.crt
install -m 640 -o root -g mosquitto "$AES_MQTT_SERVER_KEY_SOURCE" /etc/mosquitto/certs/aes-gateway.key
install -m 640 -o root -g mosquitto "$SCRIPT_DIR/mosquitto.acl" /etc/mosquitto/aes-acl
if ! openssl verify -verify_ip "$AP_IP" -CAfile /etc/mosquitto/certs/aes-ca.crt \
        /etc/mosquitto/certs/aes-gateway.crt >/dev/null; then
    echo "Gateway certificate does not verify for $AP_IP against AES_MQTT_CA_CERT_SOURCE." >&2
    exit 1
fi
if ! cmp -s \
        <(openssl x509 -in /etc/mosquitto/certs/aes-gateway.crt -pubkey -noout) \
        <(openssl pkey -in /etc/mosquitto/certs/aes-gateway.key -pubout); then
    echo "Gateway certificate and private key do not match." >&2
    exit 1
fi

plain_passwords=$(mktemp /run/aes-mqtt-passwd.XXXXXX)
trap 'rm -f "$plain_passwords"' EXIT
chmod 600 "$plain_passwords"
printf 'aes-monitor:%s\naes-receiver:%s\n' \
    "$AES_MQTT_MONITOR_PASSWORD" "$AES_MQTT_RECEIVER_PASSWORD" > "$plain_passwords"
device_credential_count=0
declare -A seen_mqtt_users=()
while IFS=: read -r mqtt_user mqtt_password; do
    if [ -z "$mqtt_user$mqtt_password" ]; then
        continue
    fi
    if ! [[ "$mqtt_user" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] \
            || [ "$mqtt_user" = "aes-monitor" ] || [ "$mqtt_user" = "aes-receiver" ] \
            || [ "${#mqtt_password}" -lt 16 ] || [ "${#mqtt_password}" -gt 128 ] \
            || ! [[ "$mqtt_password" =~ $CREDENTIAL_RE ]]; then
        echo "Invalid MQTT device credential entry for '$mqtt_user'." >&2
        exit 1
    fi
    if [[ -n "${seen_mqtt_users[$mqtt_user]:-}" ]]; then
        echo "Duplicate MQTT device username '$mqtt_user'." >&2
        exit 1
    fi
    seen_mqtt_users[$mqtt_user]=1
    printf '%s:%s\n' "$mqtt_user" "$mqtt_password" >> "$plain_passwords"
    device_credential_count=$((device_credential_count + 1))
done < "$AES_MQTT_DEVICE_CREDENTIALS_FILE"
if [ "$device_credential_count" -eq 0 ]; then
    echo "AES_MQTT_DEVICE_CREDENTIALS_FILE must contain at least one device credential." >&2
    exit 1
fi
mosquitto_passwd -U "$plain_passwords"
install -m 640 -o root -g mosquitto "$plain_passwords" /etc/mosquitto/aes-passwd

install -d -m 750 -o root -g "$AES_SERVICE_GROUP" /etc/aes
install -m 640 -o root -g "$AES_SERVICE_GROUP" "$AES_MQTT_CA_CERT_SOURCE" /etc/aes/aes-ca.crt
receiver_env=/etc/aes/receiver.env
printf 'MQTT_HOST=192.168.4.1\nMQTT_PORT=8883\nMQTT_RECEIVER_USERNAME=aes-receiver\n' > "$receiver_env"
printf 'MQTT_RECEIVER_PASSWORD=%s\nMQTT_CA_CERT=/etc/aes/aes-ca.crt\n' \
    "$AES_MQTT_RECEIVER_PASSWORD" >> "$receiver_env"
chown root:"$AES_SERVICE_GROUP" "$receiver_env"
chmod 640 "$receiver_env"

# ── 9. IP forwarding + NAT ────────────────────────────────────────────────────
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ip-forward.conf
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -C POSTROUTING -o "$UPSTREAM_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$UPSTREAM_IFACE" -j MASQUERADE
iptables -C FORWARD -i "$AP_IFACE" -o "$UPSTREAM_IFACE" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$AP_IFACE" -o "$UPSTREAM_IFACE" -j ACCEPT
netfilter-persistent save

# ── 10. Systemd service for receiver.py ──────────────────────────────────────
install -d -m 750 -o "$AES_SERVICE_USER" -g "$AES_SERVICE_GROUP" "$AES_REPO_ROOT/data/telemetry"
cp "$SCRIPT_DIR/aes-receiver.service" /etc/systemd/system/aes-receiver.service
escaped_repo_root=${AES_REPO_ROOT//\\/\\\\}
escaped_repo_root=${escaped_repo_root//&/\\&}
escaped_repo_root=${escaped_repo_root//|/\\|}
sed -i "s|__AES_REPO_ROOT__|$escaped_repo_root|g; s|__AES_SERVICE_USER__|$AES_SERVICE_USER|g" \
    /etc/systemd/system/aes-receiver.service
if grep -q '__AES_' /etc/systemd/system/aes-receiver.service; then
    echo "Receiver service template substitution failed." >&2
    exit 1
fi
systemctl daemon-reload
systemctl enable aes-receiver

# ── 11. Enable and start all services ────────────────────────────────────────
systemctl unmask hostapd
systemctl enable hostapd dnsmasq mosquitto
systemctl restart dnsmasq mosquitto
systemctl restart hostapd
systemctl start aes-receiver

echo ""
echo "=== Setup complete ==="
echo "AP SSID     : AES-Gateway"
echo "AP IP       : $AP_IP"
echo "MQTT broker : mqtts://$AP_IP:8883 (authenticated)"
echo ""
echo "Verify with:"
echo "  systemctl status hostapd mosquitto aes-receiver"
echo "  ip addr show ap0"
echo "  journalctl -u mosquitto -u aes-receiver --since today"
