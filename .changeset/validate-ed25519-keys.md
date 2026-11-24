---
'@sigstore/core': patch
'@sigstore/verify': patch
---

Validate Ed25519 public keys and the R component of Ed25519 signatures, rejecting small-order, non-canonical and off-curve points. Support Ed25519 message signatures by verifying them over the full artifact.
