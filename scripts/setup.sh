#!/bin/bash

# setup.sh - Prepares the environment and builds the router.
# Usage: sudo ./scripts/setup.sh
export PATH="$PATH:/usr/local/go/bin"
set -e

echo "SSLProxy Setup"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Root privileges required."
    exit 1
fi

echo "Checking dependencies..."

if ! command -v iptables &> /dev/null; then
    echo "ERROR: iptables not found. Install with: sudo apt install iptables"
    exit 1
fi

if ! command -v go &> /dev/null; then
    echo "WARNING: Go not found. Install with: sudo apt install golang"
fi

echo "Enabling IP forwarding..."

sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

echo "Building router..."

# Navigate to project root (parent of scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ -f "go.mod" ]; then
    go build -o sslinspectingrouter ./cmd/router
    echo "Build success: ./sslinspectingrouter"
else
    echo "WARNING: go.mod not found in $PROJECT_ROOT, skipping build."
fi

echo "Setup complete."
echo "Usage:"
echo "  1. sudo ./sslinspectingrouter"
echo "  2. Install 'ca-cert.pem' to trusted root store on clients."
