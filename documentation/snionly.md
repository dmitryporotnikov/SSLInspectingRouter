# SNI-only Mode

A privacy-preserving observation mode: HTTPS connections are **not** decrypted. The router inspects the unencrypted `ClientHello`, records the SNI and any other ClientHello metadata it can extract, then forwards the connection untouched to the original destination. The remote server's certificate chain is delivered to the client exactly as it would be in a non-proxied connection.

```bash
sudo ./sslinspectingrouter -snionly -web :3000
```

Toggle at runtime from the dashboard's [Runtime Toggles](dashboard.md#runtime-toggles).

## What is logged

* `fqdn` (SNI hostname) and source IP
* TLS record-layer and ClientHello legacy version (rendered as `TLS 1.2`, `TLS 1.3`, etc.)
* Offered cipher suites, resolved to their IANA name (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_AES_128_GCM_SHA256`)
* Compression methods (e.g. `NULL`)
* ALPN protocols, resolved to their IANA description (e.g. `HTTP/2 over TLS`, `HTTP/1.1`)
* Extension type IDs, resolved to their IANA name (e.g. `server_name`, `application_layer_protocol_negotiation`, `supported_groups`, `signature_algorithms`)
* Supported groups and signature algorithm IDs, resolved to their IANA name
* Source IP and the original destination IP/port (from `SO_ORIGINAL_DST`)

Unknown identifiers fall back to their raw hex form (`0xNNNN`) so newly registered values stay visible.

## Sample log row

```
TLS Version (record): TLS 1.2
TLS Version (client): TLS 1.2
Source IP: 10.0.0.7
Original Destination: 142.250.190.78:443
Cipher Suites (4):
  0x1301 = TLS_AES_128_GCM_SHA256
  0x1303 = TLS_CHACHA20_POLY1305_SHA256
  0xc02f = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  0xcca9 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
Compression Methods (1):
  0x00 = NULL
ALPN (2):
  "h2" = HTTP/2 over TLS
  "http/1.1" = HTTP/1.1
Extensions (5):
  0x0000 = server_name
  0x0010 = application_layer_protocol_negotiation
  0x000a = supported_groups
  0x000b = ec_point_formats
  0x000d = signature_algorithms
Supported Groups (3):
  0x001d = x25519
  0x0017 = secp256r1
  0x0018 = secp384r1
Signature Algorithms (4):
  0x0401 = rsa_pkcs1_sha256
  0x0501 = rsa_pkcs1_sha384
  0x0601 = rsa_pkcs1_sha512
  0x0403 = ecdsa_secp256r1_sha256
```

## Database layout

Rows in `Requests` are tagged `SNI-ONLY` and the response column is filled with `SNI-ONLY` once the tunnel is established. The dashboard traffic filter exposes a dedicated `sni` mode. The `GET /api/v1/status` payload includes a `sni_only_mode` boolean so the active state is always visible.

## How it works

1. HTTPS connection arrives at the proxy
2. The handler reads the first ~4KB of the TLS record (the `ClientHello`) and parses the SNI
3. `parseClientHello` extracts: TLS record + ClientHello versions, cipher suites, compression methods, ALPN, all extension types, supported groups, signature algorithms
4. `tlsnames` resolves every ID to its IANA-registered name (with hex fallback for unknown IDs)
5. The connection is forwarded to the real server (the upstream sees the real ClientHello) and traffic is tunneled unmodified
6. No local certificate is generated; the original chain is delivered to the client

## Limitations

* SNI is required. Connections to IP-only TLS targets fall back to using the original destination IP as the `fqdn` (the existing behavior of inspection-paused paths).
* The body of the ClientHello is not retained — only the fields above. PCAP export is not used in this mode (PCAP captures decrypted traffic, which we deliberately don't have here).
