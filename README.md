# SSLInspectingRouter

![Banner](banner.jpg)

This repository contains a transparent interception proxy written in Go for HTTP and HTTPS traffic on Linux. It utilizes the kernel packet filtering framework to redirect web traffic to local userspace listeners.

## Demo

![Preview](preview.gif)

## How It Works

```
+--------+                 +-------------------------+                 +------------+
| Client | <=============> |   SSLInspectingRouter   | <=============> | Destination|
+--------+   (HTTP/HTTPS)  +-------------------------+  (HTTP/HTTPS)   +------------+
              default GW   ^          |          ^           |
                           |          v          |           v
                           |     Decrypt     Re-encrypt      |
                           |                                 |
                           |                                 |
                           |        Inspect & Process        |
                           |                                 |
                           |  - Log to SQLite traffic.db     |
                           |  - Display on Dashboard         |
                           |  - Optional Content Rewrites    |
                           |                                 |
                           +---------------------------------+
                                             |
                                             v
                                        (Optionally)
                                      Export PCAP File
```

Optional egress mode: `SSLInspectingRouter -> WireGuard tunnel -> Internet`.

The application operates by manipulating `iptables` in both `nat` and `filter` tables.
It creates custom chains (`SSLPROXY`, `SSL_DISPATCH`) linked to `PREROUTING` and optional `OUTPUT` hooks to manage transparent redirection:

* **HTTP (Port 80):** Redirected to the local handler on port **8080**.
* **HTTPS (Port 443):** Redirected to the local handler on port **8443**.
* **Additional TLS ports (`-ports`)**: Redirected to the same HTTPS handler on **8443** while preserving the original destination port for upstream forwarding.

To make the Linux host function as an actual gateway, `FirewallManager` also:

* enables IPv4 forwarding (`net.ipv4.ip_forward=1`);
* allows forwarding in `filter/FORWARD` (new + established/related);
* applies `nat/POSTROUTING MASQUERADE` on the detected default egress interface.

This is what allows routed client traffic to pass through the box instead of being blackholed.

Optionally, routed traffic can be sent through a WireGuard client tunnel:

```
Client -> SSLInspectingRouter -> WireGuard tunnel -> Internet
```

This is controlled at runtime from the Web Dashboard Control Center.

### SSL/TLS Interception
For encrypted traffic, the proxy acts as a Certificate Authority (CA). It dynamically generates certificates for each host on demand (`cert.go`).
> **Note:** To avoid TLS handshake failures, clients must trust the generated `ca-cert.pem`.

## Build and Initialization

A setup script is provided to automate environment configuration. It enables IPv4 forwarding using `sysctl` and checks for required userspace tools.

Common dependencies on Debian/Ubuntu:

* `iptables`
* `iproute2` (provides `ip`)
* `wireguard-tools` (provides `wg-quick`; needed for WireGuard egress mode)
* Go compiler (`golang`)

To build the project:

```bash
sudo ./scripts/setup.sh
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
The project root also contains a `wireguard/` directory for WireGuard client configs (for example `wireguard/wg0.conf`).

### Command Line Arguments

| Command | Description |
| --- | --- |
| `sudo ./sslinspectingrouter -newcacert` | Force regeneration of the CA certificate and key. |
| `sudo ./sslinspectingrouter -allowquic` | Allow QUIC (UDP/443) traffic. By default, QUIC is blocked to enforce HTTPS over TCP. |
| `sudo ./sslinspectingrouter -ports 8443,9443` | Inspect additional TLS destination ports (comma-separated). Useful for non-standard HTTPS services. |
| `sudo ./sslinspectingrouter -truncatelog` | Truncate request/response bodies in the logs to a 4KB preview (default is full body). |
| `sudo ./sslinspectingrouter -web <addr>` | Start the Web Dashboard on the specified listen address (e.g., `:3000`, `127.0.0.1:3000`). |
| `sudo ./sslinspectingrouter -web :3000 -webtls` | Serve the Web Dashboard over HTTPS with an auto-generated self-signed certificate. |
| `sudo ./sslinspectingrouter -webcert <path> -webkey <path>` | Custom TLS cert/key paths for dashboard HTTPS mode (`-webtls`). |
| `sudo ./sslinspectingrouter -bodyartifacts` | Store binary/compressed HTTP body previews as files for offline inspection. |
| `sudo ./sslinspectingrouter -bodyartifactsdir <path>` | Custom directory for stored body artifacts (default: `logs/body-artifacts`). |
| `sudo ./sslinspectingrouter -wipedb` | Clear only traffic tables (`Requests` / `Responses`) and remove stored body artifacts before startup. Dashboard ACL/auth tables are preserved. |
| `sudo ./sslinspectingrouter -drop <list>` | Drop requests for specific FQDNs, IPs, CIDR (comma-separated). Subdomains are also blocked. |
| `sudo ./sslinspectingrouter -bypass <list>` | Bypass inspection for specific FQDNs (HTTP Host + HTTPS SNI), IPs or CIDRs. Subdomains are also bypassed. Bypassed entries are still logged, but `request` / `response` in SQLite are stored as `BYPASSED`: |
| `sudo ./sslinspectingrouter -inspectonly <IP1,IP2>` | **Allowlist Mode:** Only intercept traffic from the specified source IPs. All other traffic is ignored and bypasses the inspection entirely. |
| `sudo ./sslinspectingrouter -pcap <file>` | Export **decrypted** traffic to a PCAP file readable by Wireshark. Uses synthetic TCP streams to represent the HTTP/HTTPS payloads. |
| `sudo ./sslinspectingrouter -verbose` | Enable verbose application logging to stderr. By default, standard logs are suppressed to keep the console clean. |

### Web Dashboard Authentication

When `-web` is enabled, the dashboard API requires authentication.
When `-webtls` is also enabled, session cookies are marked secure and the dashboard is served over HTTPS.

Bootstrap admin account (created on first run if no users exist):

* Username: `admin`
* Password: `admin123`

Optional environment variables for bootstrap/admin configuration:

* `SIR_ADMIN_USER`
* `SIR_ADMIN_PASS`
* `SIR_ADMIN_NAME`
* `SIR_SESSION_SECRET` (recommended in production)

Optional environment variables for path overrides:

* `SSLINSPECTINGROUTER_REWRITES_DIR`
* `SSLINSPECTINGROUTER_WIREGUARD_DIR`

**Example: Blocking specific domains**

```bash
sudo ./sslinspectingrouter -drop test.com,test2.com
```

*(This will block `test.com`, `www.test.com`, `test2.com`, etc.)*

**Example: Combining multiple parameters**

You can combine multiple flags. For example, to block specific domains, start the web dashboard on `:3000`, and truncate logs:

```bash
sudo ./sslinspectingrouter -drop test.com,test2.com -web :3000 -truncatelog
```

**Example: Inspect non-standard TLS ports**

```bash
sudo ./sslinspectingrouter -ports 8443,9443
```

**Example: Dashboard over HTTPS (self-signed)**

```bash
sudo ./sslinspectingrouter -web :3000 -webtls
```

### WireGuard Egress (Web UI Runtime Toggle)

Use this when you want clients behind the router to reach destinations from a different public IP (for example through a VPS tunnel).

1. Start the router with dashboard enabled:

```bash
sudo ./sslinspectingrouter -web :3000
```

2. Open the dashboard as admin.
3. In `Control Center`:
   * Paste a WireGuard client config in `WireGuard Client Config` and click `Save WireGuard Config`, **or**
   * Place a `.conf` file directly into project `wireguard/` directory.
4. Enable `WireGuard Egress` toggle.

When enabled, the router switches egress NAT to the WireGuard interface so forwarded client traffic and router-originated upstream traffic exit through the tunnel.
Disable the toggle to revert to the original default egress interface.

Notes:

* The Web UI config save writes to `wireguard/wg0.conf`.
* WireGuard egress control requires `wg-quick` and `ip` binaries available on the host.

### Shutdown

The application listens for `SIGINT` and `SIGTERM` signals. When received, it initiates a graceful shutdown:

1. Attempts to bring down an active WireGuard tunnel (if enabled).
2. Removes `SSL_DISPATCH` / `SSLPROXY` redirection links and chains from iptables.
3. Removes forwarding/NAT pass-through rules created for gateway mode.

## Logging

Console output displays only the source IP and requested FQDN. Detailed logs are stored in a SQLite database.

* **Log Location:** `logs/traffic.db`
* When inspection is paused from Web UI, tunneled TLS traffic is still routed and logged as `INSPECTION PAUSED` (not `BYPASSED`).
* Binary/compressed payload previews are marked as skipped with detected `Content-Type` / `Content-Encoding` metadata. Optional body artifacts can be enabled via CLI or Web UI for admin inspection.

## Response Tampering (Rewrites)

The router can modify **HTTP and HTTPS responses on the fly** using rewrite rules stored in `rewrites/*.json`.

* **Examples & format:** `rewrites/README.md`
* **Reloading:** rules are auto-reloaded when files change (polling).

## API (v1)

The backend exposes a versioned API under `/api/v1`.

Public endpoints:

* `GET /api/v1/health`
* `POST /api/v1/auth/login`

Authenticated endpoints:

* `POST /api/v1/auth/logout`
* `GET /api/v1/auth/me`
* `GET /api/v1/status`
* `PUT /api/v1/status` (admin)
* `GET /api/v1/policy`
* `PUT /api/v1/policy` (admin)
* `GET /api/v1/traffic`
* `DELETE /api/v1/traffic` (admin, flush captured traffic)
* `GET /api/v1/traffic/{id}`
* `GET /api/v1/rewrites`
* `POST /api/v1/rewrites` (admin)
* `GET /api/v1/rewrites/{id}` (admin-managed rule by index)
* `PUT /api/v1/rewrites/{id}` (admin, managed rules)
* `DELETE /api/v1/rewrites/{id}` (admin, managed rules)
* `GET /api/v1/users` (admin)
* `POST /api/v1/users` (admin)
* `PUT /api/v1/users/{id}` (admin)
* `DELETE /api/v1/users/{id}` (admin)

`PUT /api/v1/status` accepts runtime admin settings:

* `inspection_enabled` (bool)
* `truncate_log_enabled` (bool)
* `log_nothing_enabled` (bool; when true, traffic capture logging is disabled and DB stops growing)
* `body_artifacts_enabled` (bool)
* `body_artifacts_directory` (string, optional; can also be changed from the dashboard Body Artifacts path control)
* `wireguard_enabled` (bool)
* `wireguard_config` (string; WireGuard client config content)

`GET /api/v1/status` returns runtime status for the dashboard, including:

* `allow_quic` (bool)
* `additional_tls_ports` ([]int)
* `inspect_only_sources` ([]string)
* `pcap_path` (string)
* `inspection_enabled` (bool)
* `truncate_log_enabled` (bool)
* `log_nothing_enabled` (bool)
* `body_artifacts_enabled` (bool)
* `body_artifacts_directory` (string)
* `db_size_bytes` (int64)
* `request_count` (int64)
* `active_sessions` (int64)
* `wireguard_enabled` (bool)
* `wireguard_interface` (string)
* `wireguard_config_present` (bool)
* `wireguard_config_path` (string)
* `egress_interface` (string)
* `default_egress_interface` (string)

`PUT /api/v1/policy` accepts runtime admin policy lists:

* `drop_list` ([]string)
* `bypass_list` ([]string)

`/api/v1/rewrites` powers the dashboard Rewrite Policy Studio:

* Existing rewrite files are visible in UI; external files are read-only.
* UI-created/edited rules are stored in `rewrites/dashboard-managed.rules.json`.
* Changes are saved atomically and trigger immediate engine reload.

Legacy aliases are still available for old clients:

* `/api/status`
* `/api/policy`
* `/api/traffic`
* `/api/rewrites`

### Database Schema

The database contains two primary tables: `Requests` and `Responses`.

| Column | Description |
| --- | --- |
| `timestamp` | Time of the event. |
| `source_ip` | IP address of the client. |
| `fqdn` | Fully Qualified Domain Name requested. |
| `request` / `response` | The raw header data (specific to the table). |
| `content` | The body content. Stores full body by default; max 4KB if `-truncatelog` is used. |

> **Note:** Unrecognized binary responses may appear as blobs in the `content` column.
