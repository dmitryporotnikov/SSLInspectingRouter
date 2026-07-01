#!/bin/bash

# cleanup.sh - Reverts network configurations and removes iptables rules.
# Usage: sudo ./cleanup.sh

set -e

echo "Stopping SSLProxy..."

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Root privileges required."
    exit 1
fi

echo "Cleaning up iptables rules..."

# Remove links into dispatch chains
iptables -t nat -D PREROUTING -j SSL_DISPATCH 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner 0 -j SSL_DISPATCH 2>/dev/null || true

# Backward-compat cleanup for older rule layout
iptables -t nat -D PREROUTING -j SSLPROXY 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner 0 -j SSLPROXY 2>/dev/null || true

# Flush and delete custom chains
iptables -t nat -F SSL_DISPATCH 2>/dev/null || true
iptables -t nat -X SSL_DISPATCH 2>/dev/null || true

# Flush and delete SSLPROXY chain
iptables -t nat -F SSLPROXY 2>/dev/null || true
iptables -t nat -X SSLPROXY 2>/dev/null || true

# Remove forwarding/NAT pass-through rules
while iptables -t filter -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment SSLINSPECT_FWD_EST -j ACCEPT 2>/dev/null; do :; done
while iptables -t filter -D FORWARD -m comment --comment SSLINSPECT_FWD_ALL -j ACCEPT 2>/dev/null; do :; done

DEFAULT_IFACE="$(awk '$2=="00000000" {print $1; exit}' /proc/net/route 2>/dev/null)"
if [ -n "$DEFAULT_IFACE" ]; then
    while iptables -t nat -D POSTROUTING -o "$DEFAULT_IFACE" -m comment --comment SSLINSPECT_MASQ -j MASQUERADE 2>/dev/null; do :; done
fi

echo "iptables rules cleaned."

read -p "Disable IP forwarding? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sysctl -w net.ipv4.ip_forward=0
    sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf
    echo "IP forwarding disabled."
fi

echo "Cleanup complete."
