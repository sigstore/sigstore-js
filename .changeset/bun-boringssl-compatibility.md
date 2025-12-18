---
'@sigstore/sign': patch
---

Fix BoringSSL compatibility for Bun runtime. The ephemeral signer now explicitly uses SHA-256 as the digest algorithm instead of relying on implicit defaults, enabling @sigstore/sign to work with Bun's BoringSSL implementation.
