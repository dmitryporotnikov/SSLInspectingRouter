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

if ! command -v wg-quick &> /dev/null; then
    echo "WARNING: wg-quick not found. WireGuard egress toggle in Web UI will not work until installed (sudo apt install wireguard-tools)."
fi

if ! command -v ip &> /dev/null; then
    echo "WARNING: iproute2 'ip' command not found. WireGuard status checks will be unavailable."
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

required_go_version=""
if [ -f "go.mod" ]; then
    required_go_version="$(awk '/^go / {print $2; exit}' go.mod)"
fi

go_ready_for_build=false
installed_go_version=""

if command -v go &> /dev/null; then
    installed_go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
    if [ -n "$required_go_version" ]; then
        version_match=false
        if [[ "$required_go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if [ "$installed_go_version" = "$required_go_version" ]; then
                version_match=true
            fi
        else
            required_go_minor="$(echo "$required_go_version" | awk -F. '{print $1"."$2}')"
            installed_go_minor="$(echo "$installed_go_version" | awk -F. '{print $1"."$2}')"
            if [ "$installed_go_minor" = "$required_go_minor" ]; then
                version_match=true
            fi
        fi
        if [ "$version_match" = true ]; then
            go_ready_for_build=true
            echo "Go version check: OK (installed $installed_go_version, required $required_go_version)"
        else
            echo "WARNING: Go version mismatch (installed $installed_go_version, required $required_go_version from go.mod)."
        fi
    else
        go_ready_for_build=true
        echo "WARNING: Could not read required Go version from go.mod; proceeding with installed Go $installed_go_version."
    fi
else
    echo "WARNING: Go is not installed or not in PATH."
fi

if [ "$go_ready_for_build" != true ]; then
    echo
    echo "Please install/update Go to 1.26.1 with the following commands:"
    echo "  wget https://dl.google.com/go/go1.26.1.linux-amd64.tar.gz"
    echo "  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz"
    echo "  export PATH=\$PATH:/usr/local/go/bin"
    echo "  rm go1.26.1.linux-amd64.tar.gz"
    echo
fi

if [ -f "go.mod" ]; then
    if [ "$go_ready_for_build" = true ]; then
        if go build -o sslinspectingrouter ./cmd/router; then
            echo "Build success: ./sslinspectingrouter"
        else
            echo "WARNING: Build failed. Verify Go/toolchain and retry."
        fi
    else
        echo "WARNING: Skipping build because Go is missing or does not match go.mod."
    fi
else
    echo "WARNING: go.mod not found in $PROJECT_ROOT, skipping build."
fi

echo "Setup complete."
echo "Usage:"
echo "  1. sudo ./sslinspectingrouter"
echo "  2. Install 'ca-cert.pem' to trusted root store on clients."
