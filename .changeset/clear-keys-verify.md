---
'@sigstore/core': patch
---

Default to SHA-256 for `rsa` and `ec` keys when no verification digest is provided. Preserve the existing digest selection for EdDSA and RSA-PSS keys.
