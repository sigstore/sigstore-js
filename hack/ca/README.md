# Certificate Test Data

The `Makefile` in this directory can be used to generate x509 certificates for
testing certificate chain verification logic. The extensions configured for the
various certificates are meant to mirror those used by the Fulcio CA and the
signing certificates issued by Fulcio.

The following targets are available:

* `root.crt` - Root CA
* `int.crt` - Intermediate CA signed by the root CA
* `leaf.crt` - Valid leaf certificate signed by the intermediate CA
* `poison.crt` - Certificate w/ the precert poison extension set (should fail parsing)
* `nosan.crt` - Leaf certificate signed by the intermediate CA with no SAN extension
* `badsan.crt` - Leaf certificate signed by the intermediate CA wth a SAN extension containing an unsupported type
* `nokeyusage.crt` - Leaf certificate signed by the intermediate CA with no keyUsage extension
* `invalidleaf.crt` - Certificate signed by the leaf certificate (even though leaf is not a valid CA)

**Note:** The `Makefile` doesn't work w/ the LibreSSL version of openssl
installed by default on macOS. You'll need to `brew install openssl@3` to generate
certificates.
