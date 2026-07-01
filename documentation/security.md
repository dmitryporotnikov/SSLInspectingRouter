# Security & Limitations

> **⚠️ This tool performs TLS interception by default. Use it only on networks you own and control.**

## Security checklist

* **Change the default credentials.** `admin / admin123` is the bootstrap. Set `SIR_ADMIN_USER` / `SIR_ADMIN_PASS` on first run, or rotate from the dashboard's Users page.
* **Set `SIR_SESSION_SECRET`** in production. A random 32-byte value keeps session cookies unforgeable across restarts.
* **Trust only the right hosts.** `ca-cert.pem` is generated locally. Install it on devices you intend to intercept — never on devices you don't.
* **Mind the dashboard bind address.** Bind to `127.0.0.1:3000` and use SSH tunneling, or expose via `-webtls` with proper certificates.
* **Protect the DB.** `logs/traffic.db` contains captured request/response data. Treat it with the same care as the traffic it represents.
* **Mind the PCAP file.** `-pcap` contains decrypted traffic. Same sensitivity as the live DB.

## What it does not do

* **IPv4 only.** IPv6 traffic is not intercepted. Add a parallel `ip6tables` rule chain if you need it.
* **TCP only.** UDP-based protocols other than DNS and (optionally) QUIC are not intercepted.
* **SNI-based filtering.** HTTPS filtering requires SNI. Connections to IP-only TLS targets cannot be selectively filtered by domain — they fall back to inspecting/blocking by IP via the destination recovery.
* **Non-HTTP/HTTPS over 443.** SSH-over-TLS, RDP, and other protocols that happen to use port 443 will be intercepted and broken when TLS MITM is on. Use `-snionly` or `-bypass` to leave them alone.
* **High-throughput networks.** Per-flow certificate generation is on the hot path. For high-volume networks, profile before deploying; the `-inspectonly` allowlist and `-truncatelog` options are the simplest ways to keep load down.
