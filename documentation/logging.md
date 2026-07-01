# Logging & Data Capture

The console prints only `<source_ip> <fqdn>` per request. Detailed traffic is stored in SQLite at `logs/traffic.db` (path relative to the binary).

## Log modes

The `request` and `response` columns carry a marker that tells you how a row was handled:

| Marker | Meaning |
| --- | --- |
| `GET /foo`, `200 OK`, etc. | Full MITM inspection; the cell contains the raw request/response line. |
| `BYPASSED` | The host was in the bypass list or matched a `BYPASS` firewall rule. No payload was stored. |
| `INSPECTION PAUSED` | Inspection was toggled off globally. Connection was tunneled; no payload was stored. |
| `SNI-ONLY` | [SNI-only mode](snionly.md) is active. The metadata text is stored in the `content` column of the request row. |
| `BLOCKED` | The host matched a `BLOCK` firewall rule or a `-drop` entry. |
| `TLS SNI` | The TLS handshake never produced a usable HTTP request (blocked or the connection closed before any HTTP). |

The dashboard traffic filter maps these to the `inspected`, `bypassed`, `paused`, `sni`, and `blocked` mode filters.

## Body capture

* By default, request and response bodies are stored in full
* `-truncatelog` caps each body to 4KB
* `-log_nothing` (or `log_nothing_enabled` from the dashboard) stops traffic capture entirely — the DB stops growing, and the dashboard's request count and DB size stop changing
* Binary or compressed bodies (gzip, brotli, deflate, image/*, application/octet-stream, etc.) are stored as a "skipped" preview with detected `Content-Type` / `Content-Encoding`
* `-bodyartifacts` persists those binary previews to `logs/body-artifacts/` for offline inspection

## PCAP export

`-pcap <file>` writes decrypted HTTP and HTTPS traffic to a PCAP readable in Wireshark. The HTTPS handler reconstructs the plaintext stream and writes synthetic TCP flows that Wireshark can dissect as HTTP.

> PCAP contains **decrypted traffic**. Treat it with the same care as the live traffic DB.

## Maintenance

* `-wipedb` clears the traffic tables and removes body artifacts before startup. Dashboard auth tables are preserved
* The dashboard has a "Flush" button on the traffic view that calls the same logic at runtime (admin-only)
* The DB size and total request count are surfaced in `GET /api/v1/status`

## Database schema

The two traffic tables:

| Column | Description |
| --- | --- |
| `timestamp` | RFC3339Nano UTC timestamp of the event. |
| `source_ip` | Client IP. |
| `fqdn` | SNI hostname (HTTPS) or Host header (HTTP). |
| `request` / `response` | One-line summary: HTTP method + URL, status line, or one of the markers above. |
| `content` | Headers + body preview, or the SNI-only metadata blob, or empty for `BYPASSED` / `INSPECTION PAUSED`. |
