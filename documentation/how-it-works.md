# How It Works

```
+--------+                 +-------------------------+                 +------------+
| Client | <=============> |   SSLInspectingRouter   | <=============> | Destination|
+--------+   (HTTP/HTTPS)  +-------------------------+  (HTTP/HTTPS)   +------------+
              default GW   ^          |          ^           |
                           |          v          |           v
                           |     Decrypt     Re-encrypt      |
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

Optional egress:

* `SSLInspectingRouter -> WireGuard tunnel -> Internet`
* `SSLInspectingRouter -> Tor SOCKS5 -> Internet`

WireGuard and Tor are **mutually exclusive**.

## iptables setup

The application manipulates `iptables` in both `nat` and `filter` tables. It creates custom chains (`SSLPROXY`, `SSL_DISPATCH`) linked to `PREROUTING` and an optional `OUTPUT` hook so root-local traffic is also captured:

| Source | Chain | Action |
| --- | --- | --- |
| TCP/80 | `SSLPROXY` | `REDIRECT` → `:8080` (HTTP handler) |
| TCP/443 | `SSLPROXY` | `REDIRECT` → `:8443` (HTTPS handler) |
| TCP/8443,9443,… (`-ports`) | `SSLPROXY` | `REDIRECT` → `:8443` |
| UDP/53 (`-drop`) | `SSLPROXY` | `REDIRECT` → local DNS proxy |
| UDP/443 (default) | `filter/FORWARD`, `OUTPUT` | `DROP` (QUIC block) |

`SSL_DISPATCH` lets you opt into allowlist mode via `-inspectonly` without rewriting the global rule — the dispatch chain only matches the listed source IPs and falls through otherwise.

`FirewallManager` also:

* enables `net.ipv4.ip_forward=1`
* adds `filter/FORWARD ACCEPT` (new + established/related)
* applies `nat/POSTROUTING MASQUERADE` on the detected default egress interface

That is what allows routed client traffic to actually pass through the box instead of being blackholed.

## TLS interception

For HTTPS, the proxy acts as a local CA. The `cert` package dynamically generates a per-host leaf certificate signed by `ca-cert.pem` on first connection. The `ca-cert.pem` file must be installed in the client trust store or browsers will reject the interception with a certificate error.

For SNI-only mode (`-snionly`), the proxy skips MITM entirely and forwards the original TLS stream — see [SNI-only Mode](snionly.md).

## Original destination recovery

Transparently redirected connections lose their original destination. The HTTPS handler recovers it via `SO_ORIGINAL_DST` (a Linux-specific `getsockopt`) so it can dial the real upstream — see `internal/proxy/original_dst_linux.go`.

## Shutdown

On `SIGINT` / `SIGTERM`:

1. Bring down an active WireGuard tunnel (if enabled)
2. Remove `SSL_DISPATCH` / `SSLPROXY` chains and `PREROUTING` / `OUTPUT` links
3. Drop `filter/FORWARD` and `nat/POSTROUTING MASQUERADE` rules

See `cmd/router/main.go` → `setupCleanupHandler` for the implementation.
