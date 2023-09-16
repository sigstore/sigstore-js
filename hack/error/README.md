# Erroneous Bundles

The code on this branch can be used to generate example Sigstore bundles which
exhibit a number of different error conditions. These erroneous bundles can be
useful for exercising Sigstore verification code.

## Set-up

To get started, first clone this repository and switch to the `error-bundles` branch.

Next, install the project dependencies:

```bash
npm install
```

Finally, compile the project:

```bash
npm run build
```

There are a couple of files included in this repo branch to streamline
the set-up:

- [`./hack/error/oidc`](./oidc): A fake OIDC token which can be exchanged for a Fulcio signing certificate.
- [`./hack/error/statement.json`](./statement.json): A SLSA provenance statement which can be used as the attestation source.

The claims embedded in the fake OIDC token are as follows:

```json
{
  "sub": "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
  "iss": "https://token.actions.githubusercontent.com"
}
```

## Mock Services

Mocked versions of all of the standard Sigstore services are provided which can
be manipulated in various ways to create different error conditions.

The services have been configured to all use a hard-coded private key which is
used for all signing operations (SCT/SET generation, certificate issuance, etc).

Once the mock service stack has been started, the key material for all of the
services can be retrieved by downloading the `trusted_root.json` file from the
embedded TUF repository:

```bash
curl http://localhost:8000/targets/trusted_root.json
```

The root certificates for both Fulcio and the Timestamp Authority services have
been hard-coded with a validity period that spans "2023&#8209;01&#8209;01" to "2024&#8209;01&#8209;01".

The internal clock for each of the services has been hard-coded to a value 
of "2023&#8209;02&#8209;01T00:00:00.000Z"

## Error Cases

All of the scenarios below require that you start the mock Sigstore service
stack and then invoke the `@sigstore/cli` to initiate the signing of the
artifact.

The command to sign the provenance statement and generate the bundle will 
always be the same:

```bash
npm run attest
```

To save the generated bundle to a file use the `-o` flag:

```bash
npm run attest -- -o /tmp/bundle.json
```

This will use identity in the OIDC token to sign the SLSA provenance statement
and return a Sigstore bundle.

### Expired Signing Certificate

The Fulcio-issued signing certificate is issued AFTER the expiration of the
trusted root Fulcio certificate.

```bash
npx server --ca-clock 2030-01-01
```

The internal clock of the Fulcio certificate authority is set to a time
outside of the hard-coded validity window of the CA's root certificate
(2023-01-01 to 2024-01-01).

### SCT Outside Certificate Validity Window

The Fulcio-issued signing certificate is valid, but it contains an SCT with a 
timestamp that is AFTER the expiration of the certificate to which it is
attached.

```bash
npx server --ca-clock 2023-02-01 --ctlog-clock 2023-02-02
```

The internal clock of the Fulcio certificate authority is set to a time
within the validity window of the CA's root certificate. However, the
internal clock of the CTLog is set to a value AFTER the expiration of
issued certificate (the certificate validity window will be a 10-minute span
starting at the clock value specified for the CA).

### Rekor Witnessed Time Outside Certificate Valdity Window

The `integratedTime` reported by the TLog entry is AFTER the expiration of
the Fulcio-issued signing certificate

```bash
npx server --tlog-clock 2023-02-02
```

The Fulcio-issued signing certificate has a 10-minute validity window starting
at `2023-02-01T00:00:00Z` but the Rekor-reported timestamp is `2023-02-02`.

### Rekor Body Mismatch

The `body` of the Rekor TLog entry doesn't match the signed entity.

```bash
npx server --no-tlog-strict
```

This will run the Rekor service in "non-strict" mode -- meaning that it will
ignore the proposed-entry and sign/return an empty tlog entry instead.


### TSA Witnessed Time Outside Certificate Validity Window

The TSA-returned RFC3161 timestamp is valid but has a value AFTER the
expiration of the Fulcio-issued signing certificate.

```
npx server --tsa-clock 2023-02-02
```

The Fulcio-issued signing certificate has a 10-minute validity window starting
at `2023-02-01T00:00:00Z` but the TSA-reported timestamp is `2023-02-02`.

[^1]: To apply patches, copy the patch contents to the clipboard and then execute `pbcopy | git apply` in the terminal.
