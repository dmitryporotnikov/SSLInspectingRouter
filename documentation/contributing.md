# Contributing

Contributions are welcome — features, fixes, tests, docs, and localizations.

## Workflow

1. **Fork** the repository and clone your fork.
2. Create a **topic branch** (`feature/<short-name>` or `fix/<short-name>`).
3. Make your changes. Keep the diff focused — avoid unrelated formatting churn.
4. **Test** what you can. `go test ./...` is the floor.
5. Open a **Pull Request** against `main` with:
   * A short summary
   * Any related issue numbers
   * Screenshots or logs for UI / network changes

We accept AI-generated contributions. Please review and understand the code before submitting — small changes can affect traffic routing, TLS behavior, firewall cleanup, or authentication.

## Code style

* Boring, explicit Go. Small functions, clear names, simple control flow.
* Add `ponytail:` comments when you deliberately take a shortcut so future maintainers know the ceiling and the upgrade path.
* No reflection, magic tags, codegen, or generic helpers unless there's a strong project-specific reason.
* Tests should prefer deterministic inputs and fake dependencies over live networking, root-only operations, or machine-specific state.

## Project layout (cheat sheet)

| Path | What lives here |
| --- | --- |
| `cmd/router/` | Entry point, flags, startup/shutdown. |
| `internal/proxy/` | HTTP/HTTPS interception, SNI handling, bypass tunneling, upstream proxy. |
| `internal/firewall/` | iptables, NAT, QUIC blocking, inspect-only mode. |
| `internal/cert/` | Local CA + per-host cert generation. |
| `internal/logger/` | SQLite logging, body artifacts, PCAP. |
| `internal/dashboard/` | Web dashboard, API, auth, embedded frontend. |
| `internal/rewrites/` | JSON rewrite rule loading, matching, application. |
| `internal/wireguard/`, `internal/tor/` | Egress runtime. |
| `internal/tlsnames/` | IANA TLS parameter name lookups (generated). |
| `internal/dnsproxy/` | DNS proxy used by the drop list. |
| `documentation/` | This folder. |
| `rewrites/` | User-managed rewrite JSON files. |

## Localization

See [Localization Contributing Guide](../LOCALIZATION_CONTRIBUTING.md).

## Security-sensitive changes

Any change to iptables, sysctl, WireGuard, Tor, certificate handling, or the auth/dashboard ACL must come with a clear cleanup path. Tests should cover the changed behavior, and `go test ./...` should pass before submitting.
