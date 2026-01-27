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

# Flush and delete SSLPROXY chain
iptables -t nat -F SSLPROXY 2>/dev/null || true
iptables -t nat -D PREROUTING -j SSLPROXY 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner 0 -j SSLPROXY 2>/dev/null || true
iptables -t nat -X SSLPROXY 2>/dev/null || true

echo "iptables rules cleaned."

read -p "Disable IP forwarding? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sysctl -w net.ipv4.ip_forward=0
    sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf
    echo "IP forwarding disabled."
fi

echo "Cleanup complete."
