---
'sigstore': minor
---

Add a `fetchOnConflict` option to `sign` and `attest` which fetches the existing Rekor entry when the transparency log reports that an equivalent entry already exists, instead of failing with `TLOG_CREATE_ENTRY_ERROR`.
