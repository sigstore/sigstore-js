---
'@sigstore/core': patch
'@sigstore/verify': patch
---

Validate Ed25519 public keys, rejecting small-order, non-canonical and off-curve points. Support Ed25519 message signatures by verifying them over the full artifact.
