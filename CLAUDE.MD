# CLAUDE.MD

Guidance for Claude Code and other AI assistants working in this repository.

## Project overview

SSLInspectingRouter is a Go-based transparent HTTP/HTTPS interception router for Linux. It uses iptables to redirect traffic, performs TLS MITM with locally generated certificates, logs traffic to SQLite, serves a web dashboard, supports response rewrite rules, and can route egress through WireGuard or Tor.

This is security-sensitive networking software. Small changes can affect traffic routing, TLS behavior, captured data, firewall cleanup, dashboard authentication, or the host network stack.

## Most important rule

Human-readable, maintainable code comes first.

Prefer boring, explicit, idiomatic Go over clever syntax, dense abstractions, generic helpers, reflection, or over-engineered patterns. If a future maintainer has to pause and decode the trick, rewrite it in a simpler way.

Good changes in this project should be easy to review, easy to test, and easy to reason about during an outage.

## Development commands

Use these commands from the repository root:

```bash
# Build the router binary without changing host network settings
go build -o sslinspectingrouter ./cmd/router

# Run all tests
go test ./...

# Run the setup script. This requires root and changes system networking settings.
sudo ./scripts/setup.sh

# Run the router. Root is required for iptables, forwarding, and interception.
sudo ./sslinspectingrouter -web :3000
```

The Go version in `go.mod` is the source of truth. Do not downgrade it or change toolchain assumptions without a clear reason.

## Repository layout

- `cmd/router/` - main entry point, CLI flags, service wiring, startup, and shutdown cleanup.
- `internal/proxy/` - HTTP/HTTPS interception, SNI handling, TLS MITM, bypass tunneling, upstream proxy support, response tampering integration.
- `internal/firewall/` - iptables, forwarding, NAT, QUIC blocking, inspect-only mode, egress interface switching.
- `internal/cert/` - local CA and per-host certificate generation.
- `internal/logger/` - SQLite logging, traffic capture, body artifact handling, log truncation and wipe behavior.
- `internal/dashboard/` - authenticated web dashboard, API v1 routes, embedded frontend assets, runtime controls.
- `internal/rewrites/` - JSON rewrite rule loading, matching, planning, and body/header rewrite execution.
- `internal/wireguard/` - WireGuard config, status, enable, and disable behavior.
- `internal/tor/` - Tor SOCKS status and runtime enable/disable behavior.
- `internal/pcap/` - decrypted traffic PCAP export.
- `internal/dnsproxy/` - DNS proxy behavior used for drop/block handling.
- `tests/` - integration-style package tests around major features.
- `rewrites/` - example and dashboard-managed rewrite rules.
- `scripts/` - setup/build scripts that may affect the host system.

## Code style expectations

- Write straightforward Go with clear names and simple control flow.
- Keep functions focused. Extract helpers only when they make the caller easier to read.
- Prefer explicit conditionals over compact but obscure expressions.
- Prefer small structs and interfaces that model real boundaries in this project.
- Do not introduce broad framework-style abstractions for one or two call sites.
- Avoid reflection, magic tags, code generation, global registries, or generic helpers unless there is a strong project-specific reason.
- Keep error handling explicit. Return errors with useful context using `fmt.Errorf("...: %w", err)` where appropriate.
- Use comments to explain non-obvious network, TLS, firewall, security, or concurrency behavior. Do not comment obvious code.
- Avoid unrelated formatting churn. Keep diffs focused on the requested change.

## Security and safety rules

- Be careful with host network changes. Any new iptables, sysctl, WireGuard, or Tor behavior must have a clear cleanup path.
- Preserve shutdown cleanup semantics. Firewall rules and active tunnels should be removed or restored when the program exits.
- Avoid commands in tests that require root, mutate the developer machine, or depend on external network services unless they are clearly isolated and skipped by default.

## Proxy and networking guidelines

- Preserve transparent proxy behavior. Do not accidentally turn the router into a regular explicit proxy.
- Preserve the separation between inspected, bypassed, dropped, and inspection-paused traffic.
- Keep SNI-based logic understandable and defensive. TLS ClientHello parsing is fragile by nature, so avoid clever parsing shortcuts.
- Preserve original destination handling and additional TLS port behavior.
- Be conservative with goroutines, deadlines, and connection copies. Avoid goroutine leaks and unbounded buffering.
- Do not change QUIC blocking defaults, forwarding, NAT, or egress interface behavior without updating tests and documentation.
- When changing WireGuard or Tor routing, preserve the rule that they are mutually exclusive runtime egress modes.

## Dashboard and API guidelines

- Keep `/api/v1/*` as the primary API surface.
- Preserve documented legacy aliases unless intentionally removing them in a breaking change.
- Admin-only endpoints must stay admin-only.
- Runtime controls must keep in-memory state, persisted files, and visible dashboard status consistent.
- Keep frontend/dashboard behavior simple and dependency-light unless there is a clear benefit.
- When changing localization, keep language discovery and embedded locale behavior predictable.

## Rewrite rule guidelines

- Rewrite rules live in `rewrites/*.json` and are applied in deterministic order.
- Preserve compatibility with supported rule file shapes: a single object, an array, or `{ "rules": [...] }`.
- Keep match and action semantics easy to understand from `rewrites/README.md`.
- Be careful with compressed, binary, large, and streaming bodies. Forward unchanged when safe rewriting is not possible.
- Do not add surprising rewrite side effects. Header and body changes should be explicit in the rule plan.

## Logging and data guidelines

- The project intentionally captures traffic, but changes should still minimize unnecessary data exposure.
- Keep truncation, log-nothing mode, wipe behavior, and body artifact settings clear and predictable.
- Do not change the SQLite schema casually. If a schema change is necessary, make migration behavior explicit and test it.
- PCAP export contains decrypted traffic. Treat it with the same care as traffic logs.

## Testing expectations

Before submitting code changes, run:

```bash
go test ./...
```

Add or update tests when changing:

- CLI parsing or startup wiring.
- Firewall rule construction and cleanup behavior.
- Proxy inspection, bypass, drop, or inspection-paused behavior.
- TLS/SNI parsing and original destination handling.
- Rewrite matching, planning, body rewriting, and encoding handling.
- Dashboard API permissions, auth/session behavior, and runtime status.
- WireGuard or Tor status/enable/disable behavior.
- Logger truncation, wipe, body artifact, and PCAP behavior.

Tests should favor deterministic inputs and fake dependencies over live networking, root-only operations, or machine-specific state.

## Documentation expectations

Update documentation when changing user-visible behavior, flags, endpoints, security expectations, rewrite rule format, setup requirements, or troubleshooting steps.

Important documentation files:

- `README.md`
- `rewrites/README.md`
- `LOCALIZATION_CONTRIBUTING.md`
- This `CLAUDE.MD`

## Review checklist for AI-generated changes

Before finalizing a change, verify:

- The code is easy to read aloud and explain.
- The diff is focused and avoids unrelated rewrites.
- Error handling is explicit and useful.
- Security-sensitive behavior is not weakened.
- Host network side effects have cleanup paths.
- Tests cover the changed behavior where practical.
- `go test ./...` passes, or any inability to run it is clearly stated.
- Documentation is updated when behavior changes.
