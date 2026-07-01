# Web Dashboard

Start the dashboard with `-web <addr>` (and optionally `-webtls` for HTTPS). The default bootstrap admin (`admin / admin123`) is created on first run if no users exist.

> **⚠️ Change the default credentials** before any non-lab deployment. Use `SIR_ADMIN_USER` / `SIR_ADMIN_PASS` to seed, or rotate via the dashboard's Users page.

## Authentication

* `POST /api/v1/auth/login` — public
* `POST /api/v1/auth/logout` — authenticated
* `GET  /api/v1/auth/me` — authenticated
* Session TTL: 24h, configurable via cookie (`sir_session`)
* `SIR_SESSION_SECRET` is recommended in production

When `-webtls` is enabled, session cookies are marked `Secure`.

## Control Center → Runtime Toggles

All toggles below are admin-only and take effect without a restart. The values mirror what `GET /api/v1/status` returns.

| Toggle | Status field | Effect |
| --- | --- | --- |
| Inspection | `inspection_enabled` | Pause/resume TLS MITM. When off, all HTTPS tunnels and is logged as `INSPECTION PAUSED`. |
| Truncate Log Bodies | `truncate_log_enabled` | Cap stored body content at 4KB. |
| Log Nothing | `log_nothing_enabled` | Stop writing to the traffic DB and skip body artifacts. |
| **SNI-only Mode** | `sni_only_mode` | Force transparent HTTPS forwarding. Skips MITM, preserves the original certificate chain. See [SNI-only Mode](snionly.md). |
| WireGuard Egress | `wireguard_enabled` | Route forwarded client traffic through a WireGuard client tunnel. |
| Tor Egress | `tor_enabled` | Route upstream proxy traffic through Tor SOCKS5. |
| Body Artifacts | `body_artifacts_enabled` | Persist binary/compressed bodies to `logs/body-artifacts/` for offline inspection. |

WireGuard and Tor are **mutually exclusive**. The API rejects requests that try to enable both.

WireGuard-specific controls:

* `Body Artifacts` directory — text input + Set Path button
* `WireGuard Client Config` — paste a config and click `Save WireGuard Config`. The dashboard writes it to `wireguard/wg0.conf` atomically and the engine reloads.

## Traffic view

The traffic table is filterable by:

* Free-text search across `fqdn`, `source_ip`, and request/response lines
* Host, source IP, and HTTP method filters
* Mode filter: `all`, `inspected`, `paused` (inspection paused), `sni` (SNI-only), `bypassed`, `blocked`

Click any row to open a detail view with the full request/response.

## Rewrite Policy Studio

The Rewrites tab is a CRUD UI on top of `rewrites/dashboard-managed.rules.json`. External JSON files in `rewrites/` are read-only. Save triggers an immediate engine reload. See [Response Rewrites](../rewrites/README.md) for rule format.

## Firewall

Admin-only. Two sub-tabs under **Firewall**:

* **Rules** — the existing host-based block / bypass / inspect rule list. The **Firewall Mode** toggle enables the proxy-level engine; only explicit rules block, bypass, or force inspection.
* **Outbound Ports** — destination-port allowlist for forwarded traffic. The default rule set is HTTPS (TCP 443) and DNS (TCP/UDP 53). When Firewall Mode is on, the engine installs an iptables `SSL_OUTBOUND` chain in the `filter` table that accepts the listed (protocol, port) pairs and drops everything else, and the FORWARD chain is rewired to consult it. When Firewall Mode is off, the chain is removed and FORWARD is restored to accept-all.

The outbound port list is persisted in `firewall_config` and re-applied on every startup, so a previously enabled state survives restarts. See the [API reference](api.md) for the request/response shape.

## Dual-NIC mode

The router can be run as a true gateway with separate WAN and LAN interfaces by passing `-lan <iface>` and `-wan <iface>` at startup:

* `-lan` constrains the iptables `PREROUTING → SSL_DISPATCH` jump with `-i <iface>`, so only traffic ingressing on the LAN side is intercepted.
* `-wan` pins the outbound `MASQUERADE` rule to `-o <iface>` instead of auto-detecting the default route.

Both flags are optional. With neither flag the router runs in single-NIC mode (intercept on all interfaces, auto-detect WAN). See [CLI flags](cli.md).

## Users

Admin-only. Manage accounts, roles, and passwords. The first user is seeded from `SIR_ADMIN_USER` / `SIR_ADMIN_PASS` and cannot be deleted while it is the only admin.

## Localized UI

The dashboard is localized. A language picker is on the login screen and the top bar. Available languages are discovered from the embedded locale bundles; see [Localization](../LOCALIZATION_CONTRIBUTING.md) for how to add one.
