# Egress Modes

Use these when you want clients behind the router to reach destinations through a different network path. The two modes are **mutually exclusive** — only one can be active at a time.

## WireGuard

Use when you want clients to exit through a WireGuard client tunnel (e.g. a VPS).

### Setup

1. Install `wireguard-tools` (`wg-quick`, `ip`)
2. Start the router with the dashboard:
   ```bash
   sudo ./sslinspectingrouter -web :3000
   ```
3. In the dashboard `Control Center`:
   * Paste a WireGuard client config in `WireGuard Client Config` and click `Save WireGuard Config`, **or**
   * Drop a `.conf` file into `wireguard/wg0.conf` directly
4. Toggle `WireGuard Egress` on

When enabled, the router switches the `nat/POSTROUTING MASQUERADE` rule from the default egress interface to the WireGuard interface, so forwarded client traffic and router-originated upstream traffic both exit through the tunnel. Disable the toggle to revert.

Notes:

* The dashboard writes configs to `wireguard/wg0.conf` atomically
* `wg-quick up wg0` / `wg-quick down wg0` are invoked by the runtime; both binaries must be on `$PATH`
* Mutually exclusive with Tor

## Tor

Use when you want the proxy's upstream connections (including bypass and inspection-paused tunnels) to exit via Tor.

### Setup

1. Install and run Tor on the router host. Default SOCKS endpoint: `127.0.0.1:9050`
2. Override the endpoint with `SSLINSPECTINGROUTER_TOR_SOCKS_ADDR` if needed
3. Start the router with the dashboard:
   ```bash
   sudo ./sslinspectingrouter -web :3000
   ```
4. Toggle `Tor Egress` on

The proxy dials all upstream connections through the Tor SOCKS5 proxy. Disable the toggle to restore direct routing.

Notes:

* Only upstream proxy traffic is routed through Tor. Client traffic destined for the Tor exit reaches Tor via the local SOCKS endpoint, so clients do not need any Tor configuration
* Mutually exclusive with WireGuard
