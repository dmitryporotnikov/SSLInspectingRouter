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

## Users

Admin-only. Manage accounts, roles, and passwords. The first user is seeded from `SIR_ADMIN_USER` / `SIR_ADMIN_PASS` and cannot be deleted while it is the only admin.

## Localized UI

The dashboard is localized. A language picker is on the login screen and the top bar. Available languages are discovered from the embedded locale bundles; see [Localization](../LOCALIZATION_CONTRIBUTING.md) for how to add one.
