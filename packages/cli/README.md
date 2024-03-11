# @sigstore/cli

CLI for creating and verifying Sigstore bundles.

# Usage
<!-- usage -->
```sh-session
$ npm install -g @sigstore/cli
$ sigstore COMMAND
running command...
$ sigstore (--version)
@sigstore/cli/0.6.0 darwin-arm64 node-v18.12.1
$ sigstore --help [COMMAND]
USAGE
  $ sigstore COMMAND
...
```
<!-- usagestop -->
# Commands
<!-- commands -->
* [`sigstore attach IMAGE-URI`](#sigstore-attach-image-uri)
* [`sigstore attest FILE`](#sigstore-attest-file)
* [`sigstore help [COMMAND]`](#sigstore-help-command)
* [`sigstore initialize`](#sigstore-initialize)
* [`sigstore verify BUNDLE`](#sigstore-verify-bundle)

## `sigstore attach IMAGE-URI`

attach an attestation to a container image

```
USAGE
  $ sigstore attach IMAGE-URI --attestation <value> [-u <value> -p <value>]

ARGUMENTS
  IMAGE-URI  fully qualified URI to the image

FLAGS
  -p, --password=<value>     password for the registry
  -u, --username=<value>     username for the registry
      --attestation=<value>  (required) attestation bundle to attach

DESCRIPTION
  attach an attestation to a container image

EXAMPLES
  $ sigstore attach --attestation <file> <name>{:<tag>|@<digest>}
```



## `sigstore attest FILE`

attest the supplied file

```
USAGE
  $ sigstore attest FILE [--json] [--fulcio-url <value>] [--rekor-url <value>] [--tsa-server-url <value>]
    [--tlog-upload] [--oidc-client-id <value>] [--oidc-client-secret <value>] [--oidc-issuer <value>]
    [--oidc-redirect-url <value>] [-t <value>] [-o <value>] [--timeout <value>]

ARGUMENTS
  FILE  file to attest

FLAGS
  -o, --output-file=<value>         write output to file
  -t, --payload-type=<value>        [default: application/vnd.in-toto+json] MIME or content type to apply to the DSSE
                                    envelope
      --fulcio-url=<value>          [default: https://fulcio.sigstore.dev] URL to the Sigstore PKI server
      --oidc-client-id=<value>      [default: sigstore] OIDC client ID for application
      --oidc-client-secret=<value>  OIDC client secret for application
      --oidc-issuer=<value>         [default: https://oauth2.sigstore.dev/auth] OIDC provider to be used to issue ID
                                    token
      --oidc-redirect-url=<value>   OIDC redirect URL
      --rekor-url=<value>           [default: https://rekor.sigstore.dev] URL to the Rekor transparency log
      --timeout=<value>             [default: 5] timeout in seconds for API requests
      --[no-]tlog-upload            whether or not to upload entry to the transparency log
      --tsa-server-url=<value>      URL to the Timestamping Authority

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  attest the supplied file

EXAMPLES
  $ sigstore attest ./statement.json
```



## `sigstore help [COMMAND]`

Display help for sigstore.

```
USAGE
  $ sigstore help [COMMAND] [-n]

ARGUMENTS
  COMMAND  Command to show help for.

FLAGS
  -n, --nested-commands  Include all nested commands in the output.

DESCRIPTION
  Display help for sigstore.
```



## `sigstore initialize`

initialize the Sigstore TUF root to retrieve trusted certificates and keys for verification

```
USAGE
  $ sigstore initialize [--mirror <value>] [--root <value>] [--cache-path <value>] [--force]

FLAGS
  --cache-path=<value>  Absolute path to the directory to be used for caching downloaded TUF metadata and targets
  --force               force initialization even if the cache already exists
  --mirror=<value>      [default: https://tuf-repo-cdn.sigstore.dev] URL to the Sigstore TUF repository
  --root=<value>        path to the initial trusted root. Defaults to the embedded root.

DESCRIPTION
  initialize the Sigstore TUF root to retrieve trusted certificates and keys for verification

ALIASES
  $ sigstore init

EXAMPLES
  $ sigstore initialize
```



## `sigstore verify BUNDLE`

verify the supplied .sigstore bundle file

```
USAGE
  $ sigstore verify BUNDLE [--json] [--tlog-threshold <value>] [--ctlog-threshold <value>]
    [--certificate-identity-email <value> --certificate-issuer <value>] [--certificate-identity-uri <value> ]
    [--tuf-mirror-url <value>] [--tuf-root-path <value>] [--tuf-cache-path <value>] [--tuf-force-cache] [--blob-file
    <value> | --blob <value>]

ARGUMENTS
  BUNDLE  bundle to verify

FLAGS
  --blob=<value>                        Base64 encoded data to verify. Only required if bundle was not signed using
                                        attest
  --blob-file=<value>                   File containing data to verify. Only required if bundle was not signed using
                                        attest
  --certificate-identity-email=<value>  Email address which must appear in the signing certificate's Subject Alternative
                                        Name (SAN) extension. Not verified if no value is supplied
  --certificate-identity-uri=<value>    URI which must appear in the signing certificate's Subject Alternative Name
                                        (SAN) extension. Not verified if no value is supplied
  --certificate-issuer=<value>          Value that must appear in the signing certificate's issuer extension (OID
                                        1.3.6.1.4.1.57264.1.1 or 1.3.6.1.4.1.57264.1.8). Not verified if no value is
                                        supplied
  --ctlog-threshold=<value>             [default: 1] number of certificate transparency log entries required to verify
  --tlog-threshold=<value>              [default: 1] number of transparency log entries required to verify
  --tuf-cache-path=<value>              Absolute path to the directory to be used for caching downloaded TUF metadata
                                        and targets
  --tuf-force-cache                     Whether to give precedence to cached, un-expired TUF metadata and targets over
                                        remote versions
  --tuf-mirror-url=<value>              Base URL for the Sigstore TUF repository
  --tuf-root-path=<value>               Path to the initial trust root for the TUF repository

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  verify the supplied .sigstore bundle file

EXAMPLES
  $ sigstore verify ./bundle.sigstore
```


<!-- commandsstop -->
