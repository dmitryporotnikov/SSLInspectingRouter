# Command-Line Interface

Root is required for iptables, IP forwarding, and transparent interception.

```bash
sudo ./sslinspectingrouter [flags]
```

On the first run, the router generates `ca-cert.pem` and `ca-key.pem` in the project root. These are reused on subsequent runs. Drop a WireGuard client config into `wireguard/wg0.conf` if you plan to enable that egress.

## Flags

| Flag | Description |
| --- | --- |
| `-drop <list>` | Drop requests for FQDNs / IPs / CIDRs. Subdomains of dropped FQDNs are also blocked. |
| `-bypass <list>` | Bypass inspection for FQDNs (HTTP Host + HTTPS SNI), IPs, or CIDRs. Subdomains are also bypassed. Bypassed entries are still logged, marked `BYPASSED`. |
| `-inspectonly <ip,…>` | Allowlist mode: only intercept traffic from the listed source IPs. All other sources bypass entirely. |
| `-ports <list>` | Inspect additional TLS destination ports (e.g. `8443,9443`). |
| `-newcacert` | Force regeneration of the CA certificate and key. |
| `-allowquic` | Allow QUIC (UDP/443). QUIC is blocked by default to force TCP-based HTTPS. |
| `-truncatelog` | Truncate request/response bodies in SQLite to a 4KB preview (default: full body). |
| `-wipedb` | Clear only the traffic tables and stored body artifacts before startup. Dashboard auth tables are preserved. |
| `-web <addr>` | Start the Web Dashboard on the given listen address (e.g. `:3000`). |
| `-webtls` | Serve the dashboard over HTTPS with an auto-generated self-signed certificate. |
| `-webcert <path>` `-webkey <path>` | Custom TLS cert/key paths for dashboard HTTPS mode. |
| `-bodyartifacts` | Store binary/compressed HTTP body previews to disk for offline inspection. |
| `-bodyartifactsdir <path>` | Custom directory for stored body artifacts (default `logs/body-artifacts`). |
| `-pcap <file>` | Export **decrypted** traffic to a PCAP file readable in Wireshark. Synthetic TCP streams are used. |
| `-snionly` | [SNI-only mode](snionly.md) — forward HTTPS transparently, log only SNI + ClientHello metadata. |
| `-verbose` | Enable verbose application logging to stderr. Standard logs are suppressed by default. |

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SIR_ADMIN_USER` | Bootstrap admin username (default `admin`). |
| `SIR_ADMIN_PASS` | Bootstrap admin password (default `admin123`). |
| `SIR_ADMIN_NAME` | Display name for the bootstrap admin. |
| `SIR_SESSION_SECRET` | Random secret for signing session cookies. **Set in production.** |
| `SSLINSPECTINGROUTER_REWRITES_DIR` | Override the rewrite rules directory. |
| `SSLINSPECTINGROUTER_WIREGUARD_DIR` | Override the WireGuard config directory. |
| `SSLINSPECTINGROUTER_TOR_SOCKS_ADDR` | Override the Tor SOCKS endpoint (default `127.0.0.1:9050`). |

## Common combinations

```bash
# Block specific domains + dashboard
sudo ./sslinspectingrouter -drop test.com,test2.com -web :3000

# Compact logs, retain full structure
sudo ./sslinspectingrouter -truncatelog -web :3000

# Inspect non-standard TLS ports
sudo ./sslinspectingrouter -ports 8443,9443

# Dashboard over HTTPS
sudo ./sslinspectingrouter -web :3000 -webtls

# Passive observation, no MITM
sudo ./sslinspectingrouter -snionly -web :3000
```

## Runtime toggles

Many of these flags have dashboard equivalents that can be flipped without restarting — see [Web Dashboard → Runtime Toggles](dashboard.md#runtime-toggles).
