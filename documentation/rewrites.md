# Response Rewrites

JSON rules that modify HTTP and HTTPS responses on the fly — useful for injecting CORS headers, swapping in a replacement script, or stripping tracking pixels.

The full rule format, examples, and best practices live in:

→ [Response Rewrites Guide](../rewrites/README.md)

Highlights:

* Rules live in `rewrites/*.json`
* Files in that directory are read-only from the dashboard; rules created in the dashboard are stored in `rewrites/dashboard-managed.rules.json`
* The engine reloads automatically when files change
* Bodies are only tampered with for `Content-Type` and `Content-Encoding` values the engine understands (identity, gzip, deflate). Brotli and other encodings are forwarded unchanged.
