---
'sigstore': major
---

Removes `oidcIssuer`, `oidcClient`, `oidcClientSecret`, and `oidcRedirectURL` from the options for the `sign` and `attest` functions. The OAuth identity provider that was associated with these options has been relocated to the `@sigstore/cli` package.
