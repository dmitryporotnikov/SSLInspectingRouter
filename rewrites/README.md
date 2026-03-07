# Response Tampering (Rewrites)

The router can modify **HTTP and HTTPS responses on the fly** using JSON rewrite rules stored in this folder.

Rules are loaded from `rewrites/*.json` on startup and **auto-reloaded** when files change (polling, ~1s).
If multiple rules match a response, they are applied in **filename order** (lexicographic), then in the order they appear in the file.

## JSON rule format

Each `*.json` file can contain:

- a single rule object, or
- an array of rule objects, or
- `{ "rules": [ ... ] }`

### Rule object

```json
{
  "name": "my-rule",
  "enabled": true,
  "match": {
    "host": "example.com",
    "host_regex": ".*\\.example\\.com$",
    "path_prefix": "/api/",
    "path_regex": "^/api/v[0-9]+/",
    "method": "GET",
    "methods": ["GET", "POST"],
    "status": 200,
    "statuses": [200, 201],
    "content_type_contains": "application/json",
    "content_type_regex": "text/(html|plain)",
    "request_header_contains": { "User-Agent": "Android" },
    "response_header_contains": { "Server": "nginx" }
  },
  "actions": {
    "set_headers": { "X-Debug": "true" },
    "add_headers": { "Set-Cookie": "debug=1" },
    "del_headers": ["Content-Security-Policy"],
    "replace_body": [
      { "from": "Google", "to": "MyApp" }
    ],
    "replace_body_regex": [
      { "pattern": "\"featureFlag\"\\s*:\\s*false", "replace": "\"featureFlag\": true" }
    ]
  }
}
```

Notes:

- `host` matching is **case-insensitive**.
- `host` is matched against the hostname **without the port** (e.g. `example.com`, not `example.com:443`).
- `path_*` and `*_regex` match against the request **URI** (path + query string).
- `content_type_contains` is **case-insensitive**.
- Body tampering supports `Content-Encoding`: `identity`, `gzip`, `deflate`.
- If any enabled rule could rewrite the **body** for a given request, the proxy forces upstream `Accept-Encoding: gzip` (to avoid brotli responses that can't be rewritten).
- Body tampering buffers up to ~10MiB of response body (decoded body up to ~20MiB); larger/streaming responses are forwarded without body modifications.

## Examples

### Replace string in HTML + add debug header

Create `rewrites/001-google-to-myapp.json`:

```json
{
  "name": "google-to-myapp",
  "enabled": true,
  "match": { "content_type_contains": "text/html" },
  "actions": {
    "set_headers": { "X-Debug": "true" },
    "replace_body": [{ "from": "Google", "to": "MyApp" }]
  }
}
```

### Inject header for a single API route

```json
{
  "name": "api-debug-header",
  "enabled": true,
  "match": { "host": "api.example.com", "path_prefix": "/v1/" },
  "actions": { "set_headers": { "X-Debug": "true" } }
}
```
