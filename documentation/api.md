# API Reference

Versioned JSON API under `/api/v1`. Auth is a session cookie returned by `POST /api/v1/auth/login`. Admin-only routes are marked.

## Endpoints

### Public

* `GET  /api/v1/health`
* `POST /api/v1/auth/login`
* `GET  /api/v1/localization/languages`

### Authenticated

* `POST /api/v1/auth/logout`
* `GET  /api/v1/auth/me`
* `GET  /api/v1/status`
* `GET  /api/v1/policy`
* `GET  /api/v1/traffic`
* `GET  /api/v1/traffic/{id}`
* `GET  /api/v1/rewrites`
* `GET  /api/v1/rewrites/{id}` — managed rule
* `GET  /api/v1/firewall/status`
* `GET  /api/v1/firewall/rules`
* `GET  /api/v1/firewall/rules/{id}`
* `GET  /api/v1/firewall/outbound-ports`

### Admin-only

* `PUT  /api/v1/status` — runtime toggles (see below)
* `PUT  /api/v1/policy` — drop / bypass lists
* `DELETE /api/v1/traffic` — flush traffic
* `POST /api/v1/rewrites` — create managed rule
* `PUT  /api/v1/rewrites/{id}` — update managed rule
* `DELETE /api/v1/rewrites/{id}` — delete managed rule
* `POST /api/v1/firewall/rules`
* `PUT  /api/v1/firewall/rules/{id}`
* `DELETE /api/v1/firewall/rules/{id}`
* `PUT  /api/v1/firewall/outbound-ports` — replace outbound port allowlist
* `GET  /api/v1/users`
* `POST /api/v1/users`
* `PUT  /api/v1/users/{id}`
* `DELETE /api/v1/users/{id}`

## Legacy aliases

For backward compatibility the following unversioned aliases are also served:

* `/api/status`
* `/api/policy`
* `/api/rewrites`
* `/api/rewrites/{id}`

## `PUT /api/v1/status`

```json
{
  "inspection_enabled": true,
  "truncate_log_enabled": false,
  "log_nothing_enabled": false,
  "sni_only_mode": false,
  "body_artifacts_enabled": false,
  "body_artifacts_directory": "",
  "wireguard_enabled": false,
  "wireguard_config": "",
  "tor_enabled": false
}
```

All fields are optional. WireGuard and Tor cannot both be `true` — the request is rejected with `400`.

## `GET /api/v1/status`

Returns runtime state for the dashboard. Notable fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `inspection_enabled` | bool | TLS MITM is active. |
| `sni_only_mode` | bool | SNI-only mode is active. |
| `truncate_log_enabled` | bool | 4KB body cap is in effect. |
| `log_nothing_enabled` | bool | Traffic capture is paused. |
| `body_artifacts_enabled` | bool | Binary previews are written to disk. |
| `body_artifacts_directory` | string | Where artifacts are written. |
| `allow_quic` | bool | QUIC is allowed. |
| `additional_tls_ports` | int[] | Extra ports from `-ports`. |
| `inspect_only_sources` | string[] | Source IPs in allowlist mode. |
| `pcap_path` | string | PCAP export path, or empty. |
| `wireguard_enabled` | bool | WireGuard egress is active. |
| `wireguard_interface` | string | Active `wg` interface name. |
| `wireguard_config_present` | bool | A config file was found. |
| `wireguard_config_path` | string | Path to the active config. |
| `tor_enabled` | bool | Tor egress is active. |
| `tor_socks_address` | string | Tor SOCKS endpoint. |
| `tor_reachable` | bool | SOCKS endpoint responded at last check. |
| `tor_last_error` | string | Last SOCKS error, if any. |
| `egress_interface` | string | Currently active egress interface. |
| `default_egress_interface` | string | Default egress interface at startup. |
| `db_size_bytes` | int64 | Size of the traffic DB. |
| `request_count` | int64 | Total rows in `Requests`. |
| `active_sessions` | int64 | Active dashboard sessions. |

## `PUT /api/v1/policy`

```json
{
  "drop_list": ["example.com", "203.0.113.10", "10.10.0.0/16"],
  "bypass_list": ["internal.example.com"]
}
```

Both fields are optional. Supports FQDNs, IPs, and CIDRs. Comma-separated or one-per-line on the dashboard side.

## `GET /api/v1/traffic`

Query parameters:

| Param | Type | Default | Meaning |
| --- | --- | --- | --- |
| `limit` | int | 50 | 1–500 rows. |
| `offset` | int | 0 | Pagination offset. |
| `q` | string | — | Free-text search. |
| `host` | string | — | Filter on `fqdn` LIKE. |
| `source_ip` | string | — | Filter on `source_ip` LIKE. |
| `method` | string | — | Filter on request method. |
| `mode` | string | — | `inspected`, `paused`, `sni`, `bypassed`, or `blocked`. |

Response rows are `TrafficEntry` objects (id, timestamp, source_ip, host, method, url, status, mode, request_line).

## `GET /api/v1/firewall/status`

Returns whether the proxy-layer firewall mode is on. The `enabled` flag controls the proxy's host-based block/bypass/inspect engine; the iptables `SSL_OUTBOUND` chain tracks the same flag combined with the outbound port allowlist.

```json
{ "enabled": false }
```

## `GET /api/v1/firewall/rules`

Returns the persisted host-based block/bypass/inspect rule list. Each rule has `id`, `priority`, `enabled`, `action` (`block` | `bypass` | `inspect`), `block_mode` (`display_page` | `silent_drop` for blocked rules), and a `match` object (`host`, `host_regex`, `ip`, `cidr`).

```json
{ "rules": [ ... ], "total": 3 }
```

## `POST /api/v1/firewall/rules`

Create a rule. `action` must be `block`, `bypass`, or `inspect`. When `action` is `block` and `block_mode` is omitted, defaults to `display_page`. Response is `201 Created` with the persisted rule.

## `PUT /api/v1/firewall/rules/{id}`

Replace a rule. Same shape as POST.

## `DELETE /api/v1/firewall/rules/{id}`

Remove a rule. Returns `204 No Content`.

## `GET /api/v1/firewall/outbound-ports`

Returns the persisted outbound port allowlist and the current firewall enabled state. The list is enforced as a default-DROP iptables allowlist and is only installed when firewall mode is on.

```json
{
  "enabled": true,
  "ports": [
    { "port": 443, "protocol": "tcp" },
    { "port": 53, "protocol": "tcp" },
    { "port": 53, "protocol": "udp" }
  ]
}
```

## `PUT /api/v1/firewall/outbound-ports`

Replace the outbound port allowlist. The server validates `port` (1–65535) and `protocol` (`tcp` | `udp`), drops invalid entries, and collapses duplicates before persisting. The iptables `SSL_OUTBOUND` chain is rebuilt on save.

```json
{ "ports": [ { "port": 443, "protocol": "tcp" } ] }
```

## `PUT /api/v1/firewall/rules` (toggle)

Toggles firewall mode. The body is `{ "enabled": true | false }`. Turning mode on applies explicit proxy rules and the outbound port allowlist without creating new rules.
