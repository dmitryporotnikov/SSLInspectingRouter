# SSLInspectingRouter

![Preview](preview.gif)

This repository contains a transparent interception proxy written in Go for HTTP and HTTPS traffic on Linux. It utilizes the kernel packet filtering framework to redirect web traffic to local userspace listeners.

## How It Works

The application operates by manipulating the `iptables` `nat` table. It creates a custom `SSLPROXY` chain linked to the `PREROUTING` hook to manage traffic redirection:

* **HTTP (Port 80):** Redirected to the local handler on port **8080**.
* **HTTPS (Port 443):** Redirected to the local handler on port **8443**.

The `FirewallManager` (located in `firewall.go`) manages these rules and ensures the environment is restored when the process ends.

### SSL/TLS Interception
For encrypted traffic, the proxy acts as a Certificate Authority (CA). It dynamically generates certificates for each host on demand (`cert.go`).
> **Note:** To avoid TLS handshake failures, clients must trust the generated `ca-cert.pem`.

## Build and Initialization

A setup script is provided to automate environment configuration. It enables IPv4 forwarding using `sysctl` and checks for the Go compiler and netfilter userspace tools.

To build the project:

```bash
sudo ./setup.sh
```

If the build is successful, a binary named `sslinspectingrouter` will be created in the project root.

## Execution

**Privileged access (root) is required** for network stack manipulation and interception.

### Basic Usage

Run the binary as the root user:

```bash
sudo ./sslinspectingrouter
```

On the first run, the router generates `ca-cert.pem` and `ca-key.pem`. These are reused on subsequent runs.

### Command Line Arguments

| Command | Description |
| --- | --- |
| `sudo ./sslinspectingrouter -newcacert` | Force regeneration of the CA certificate and key. |
| `sudo ./sslinspectingrouter -allowquic` | Allow QUIC (UDP/443) traffic. By default, QUIC is blocked to enforce HTTPS over TCP. |
| `sudo ./sslinspectingrouter -truncatelog` | Truncate request/response bodies in the logs to a 4KB preview (default is full body). |
| `sudo ./sslinspectingrouter -web <addr>` | Start the Web Dashboard on the specified address (e.g., `:3000`). |
| `sudo ./sslinspectingrouter -wipedb` | Clear the traffic database before startup. |
| `sudo ./sslinspectingrouter -drop <list>` | Drop requests for specific FQDNs, IPs, CIDR (comma-separated). Subdomains are also blocked. |
| `sudo ./sslinspectingrouter -bypass <list>` | Bypass inspection for specific FQDNs (HTTP Host + HTTPS SNI), IPs or CIDRs. Subdomains are also bypassed. Bypassed entries are still logged, but `request` / `response` in SQLite are stored as `BYPASSED`: |
| `sudo ./sslinspectingrouter -inspectonly <IP1,IP2>` | **Allowlist Mode:** Only intercept traffic from the specified source IPs. All other traffic is ignored and bypasses the inspection entirely. |
| `sudo ./sslinspectingrouter -pcap <file>` | Export **decrypted** traffic to a PCAP file readable by Wireshark. Uses synthetic TCP streams to represent the HTTP/HTTPS payloads. |

**Example: Blocking specific domains**

```bash
sudo ./sslinspectingrouter -drop test.com,test2.com

```

*(This will block `test.com`, `www.test.com`, `test2.com`, etc.)*

### Shutdown

The application listens for `SIGINT` and `SIGTERM` signals. When received, it initiates a graceful shutdown:

1. Flushes the `SSLPROXY` chain from iptables.
2. Removes redirection rules to prevent network blackholing.

## Logging

Console output displays only the source IP and requested FQDN. Detailed logs are stored in a SQLite database.

* **Log Location:** `logs/traffic.db`

### Database Schema

The database contains two primary tables: `Requests` and `Responses`.

| Column | Description |
| --- | --- |
| `timestamp` | Time of the event. |
| `source_ip` | IP address of the client. |
| `fqdn` | Fully Qualified Domain Name requested. |
| `request` / `response` | The raw header data (specific to the table). |
| `content` | The body content. Stores full body by default; max 4KB if `-truncatelog` is used. |

> **Note:** Binary responses may appear as blobs in the `content` column.

