---
"@sigstore/verify": patch
---

Deduplicate transparency-log entries before counting them toward `tlogThreshold`, so repeated copies of a single entry no longer over-count. This matches the existing duplicate checks for timestamps and SCTs in the same verifier.
