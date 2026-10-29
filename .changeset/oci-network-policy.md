---
'@sigstore/oci': minor
'@sigstore/cli': minor
---

Harden registry authentication and redirect handling. Requests now require HTTPS and public network destinations unless an origin is explicitly allowed via `fetchOpts.allowedPrivateOrigins` (or `sigstore attach --allow-private-origin`). Configured proxies remain supported; destination DNS checks apply only to direct connections.
