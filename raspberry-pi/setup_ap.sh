#!/usr/bin/env bash
# setup_ap.sh — Run once as root on the Raspberry Pi 4 (Bookworm).
# Configures AP+STA simultaneous mode: wlan0 stays connected to home WiFi,
# virtual ap0 becomes the access point for ESP32 devices on 192.168.4.0/24.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    python3-paho-mqtt iptables-persistent rfkill

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
ip addr add "$AP_IP/$AP_NETMASK" dev "$AP_IFACE" 2>/dev/null || true
ip link set "$AP_IFACE" up

# ── 6. Copy hostapd config ────────────────────────────────────────────────────
cp "$SCRIPT_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
# Handle both `#DAEMON_CONF=` and `DAEMON_CONF=""` variants on Bookworm
sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# ── 7. Copy dnsmasq config ────────────────────────────────────────────────────
[ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
cp "$SCRIPT_DIR/dnsmasq.conf" /etc/dnsmasq.conf

# ── 8. Copy mosquitto config ──────────────────────────────────────────────────
cp "$SCRIPT_DIR/mosquitto.conf" /etc/mosquitto/conf.d/aes.conf

# ── 9. IP forwarding + NAT ────────────────────────────────────────────────────
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ip-forward.conf
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -C POSTROUTING -o "$UPSTREAM_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$UPSTREAM_IFACE" -j MASQUERADE
iptables -C FORWARD -i "$AP_IFACE" -o "$UPSTREAM_IFACE" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$AP_IFACE" -o "$UPSTREAM_IFACE" -j ACCEPT
netfilter-persistent save

# ── 10. Systemd service for receiver.py ──────────────────────────────────────
cp "$SCRIPT_DIR/aes-receiver.service" /etc/systemd/system/
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
echo "AP Password : CHANGE_ME_ON_DEVICE"
echo "AP IP       : $AP_IP"
echo "MQTT broker : mqtt://$AP_IP:1883"
echo ""
echo "Verify with:"
echo "  systemctl status hostapd mosquitto aes-receiver"
echo "  ip addr show ap0"
echo "  mosquitto_sub -h $AP_IP -t 'aes/telemetry/+'"
