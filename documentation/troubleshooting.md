# Troubleshooting

## Browser shows TLS/SSL errors after enabling interception

1. The client doesn't trust the CA. Import `ca-cert.pem` into the client's trusted root store.
2. Restart the browser (and on some platforms, the system networking stack) after importing.
3. On mobile devices, some apps have their own certificate stores and won't respect the system store. Use SNI-only mode (`-snionly`) if you only need metadata.
4. For apps that pin certificates (HSTS preload, public key pinning), interception will fail by design.

## Traffic not being redirected

1. Are you running as root? (`sudo ./sslinspectingrouter`)
2. Is `net.ipv4.ip_forward=1`? Check with `sysctl net.ipv4.ip_forward`.
3. Do iptables rules exist?
   ```bash
   sudo iptables -t nat -L SSLPROXY -n -v
   sudo iptables -t nat -L SSL_DISPATCH -n -v
   ```
4. Is the client using this host as its default gateway? Run `ip route` on the client.

## Database growing too large

1. `-truncatelog` caps bodies to 4KB.
2. Toggle `Log Nothing` from the dashboard (or `-log_nothing` flag) to pause capture entirely.
3. Run with `-wipedb` periodically, or hit the dashboard's Flush button.
4. Keep `Body Artifacts` off unless you actually need binary previews.

## WireGuard egress not working

1. `wg-quick` and `ip` are installed and on `$PATH`.
2. The config saved by the dashboard is a valid WireGuard client config.
3. `ip link show wg0` reports the interface up.
4. Check `journalctl -u wg-quick@wg0` for `wg-quick` errors.

## Tor egress not working

1. Tor is running locally: `systemctl status tor`.
2. The SOCKS endpoint responds: `curl --socks5 127.0.0.1:9050 http://check.torproject.org`.
3. The override `SSLINSPECTINGROUTER_TOR_SOCKS_ADDR` matches your Tor config.

## Application won't start

1. Ports 8080/8443 may already be in use: `ss -tlnp | grep -E '8080|8443'`
2. Another instance is running: `ps aux | grep sslinspectingrouter`
3. Leftover iptables rules from a previous crash. Clean them manually:
   ```bash
   sudo iptables -t nat -F SSLPROXY
   sudo iptables -t nat -F SSL_DISPATCH
   sudo iptables -t nat -X SSLPROXY
   sudo iptables -t nat -X SSL_DISPATCH
   sudo iptables -t filter -F FORWARD
   ```

## Web dashboard inaccessible

1. Confirm `-web` was passed.
2. Check the listen port: `ss -tlnp | grep <port>`.
3. If bound to `127.0.0.1`, access locally or use SSH port forwarding.
4. Confirm the host firewall allows the port.

## High CPU usage

1. Lots of simultaneous connections plus per-host cert generation is expensive. Consider `-inspectonly` to scope to a smaller set of sources.
2. Use `-truncatelog` to skip large-body processing.
3. Profile with `go tool pprof` if you have a custom build.

## Cleanup is incomplete after Ctrl+C

The shutdown handler runs in a goroutine and removes `SSLPROXY` / `SSL_DISPATCH` chains, `PREROUTING` / `OUTPUT` links, the `FORWARD ACCEPT` rules, and the active WireGuard tunnel. If a process is killed with `SIGKILL`, the cleanup won't run — use the manual iptables cleanup above.

## "Authentication service unavailable" on the dashboard

The traffic logger and the dashboard share a single SQLite database. Under heavy log volume, a dashboard write (session lookup, `last_seen_at` update) can briefly contend with the proxy's traffic writes and hit `SQLITE_BUSY`. The router handles this with:

* WAL journal mode + `synchronous = NORMAL` (faster commits, still safe)
* `busy_timeout = 3000` (a contended query waits up to 3s for the lock)
* 3-attempt retry with backoff on the session lookup
* 3-attempt retry with backoff on the `last_seen_at` touch

If you still see the message, the most common causes are:

1. A very hot log path overwhelming the disk. Drop to `-truncatelog` or `-log_nothing` while you reproduce.
2. The DB is on a network or USB drive. Move it to local SSD/HDD.
3. A long-running read transaction elsewhere. Avoid leaving the dashboard open on a slow filter while traffic is heavy.
4. The WAL file grew large. The router runs a passive `wal_checkpoint` every 5 minutes; restart the process to force one if you need to reclaim space now.

Genuine lock-timeout errors return `503` with `authentication service temporarily unavailable` and a distinct message — anything else returns `500` and is logged as a bug.
