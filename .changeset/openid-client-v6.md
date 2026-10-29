---
"@sigstore/cli": patch
---

Upgrade openid-client to v6 and migrate browser authentication while retaining PKCE, state, nonce, and ID-token signature validation. OpenID Connect issuers must now use HTTPS; localhost callback URLs continue to use HTTP.
