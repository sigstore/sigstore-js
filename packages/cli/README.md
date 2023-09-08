# @sigstore/cli

CLI for creating and verifying Sigstore bundles.

# Usage
<!-- usage -->
```sh-session
$ npm install -g @sigstore/cli
$ sigstore COMMAND
running command...
$ sigstore (--version)
@sigstore/cli/0.2.1 darwin-arm64 node-v18.12.1
$ sigstore --help [COMMAND]
USAGE
  $ sigstore COMMAND
...
```
<!-- usagestop -->
# Commands
<!-- commands -->
* [`sigstore attest FILE`](#sigstore-attest-file)
* [`sigstore help [COMMANDS]`](#sigstore-help-commands)
* [`sigstore initialize`](#sigstore-initialize)
* [`sigstore verify BUNDLE`](#sigstore-verify-bundle)

## `sigstore attest FILE`

attest the supplied file

```
USAGE
  $ sigstore attest FILE [--json] [--fulcio-url <value>] [--rekor-url <value>] [--tsa-server-url <value>]
    [--tlog-upload] [--oidc-client-id <value>] [--oidc-client-secret <value>] [--oidc-issuer <value>]
    [--oidc-redirect-url <value>] [-t <value>] [-o <value>]

ARGUMENTS
  FILE  file to attest

FLAGS
  -o, --output-file=<value>     write output to file
  -t, --payload-type=<value>    [default: application/vnd.in-toto+json] MIME or content type to apply to the DSSE
                                envelope
  --fulcio-url=<value>          [default: https://fulcio.sigstore.dev] URL to the Sigstore PKI server
  --oidc-client-id=<value>      [default: sigstore] OIDC client ID for application
  --oidc-client-secret=<value>  OIDC client secret for application
  --oidc-issuer=<value>         [default: https://oauth2.sigstore.dev/auth] OIDC provider to be used to issue ID token
  --oidc-redirect-url=<value>   OIDC redirect URL
  --rekor-url=<value>           [default: https://rekor.sigstore.dev] URL to the Rekor transparency log
  --[no-]tlog-upload            whether or not to upload entry to the transparency log
  --tsa-server-url=<value>      URL to the Timestamping Authority

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  attest the supplied file

EXAMPLES
  $ sigstore attest ./statement.json
```



## `sigstore help [COMMANDS]`

Display help for sigstore.

```
USAGE
  $ sigstore help [COMMANDS] [-n]

ARGUMENTS
  COMMANDS  Command to show help for.

FLAGS
  -n, --nested-commands  Include all nested commands in the output.

DESCRIPTION
  Display help for sigstore.
```



## `sigstore initialize`

initialize the Sigstore TUF root to retrieve trusted certificates and keys for verification

```
USAGE
  $ sigstore initialize [--mirror <value>] [--root <value>] [--force]

FLAGS
  --force           force initialization even if the cache already exists
  --mirror=<value>  [default: https://tuf-repo-cdn.sigstore.dev] URL to the Sigstore TUF repository
  --root=<value>    path to the initial trusted root. Defaults to the embedded root.

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

ARGUMENTS
  BUNDLE  bundle to verify

FLAGS
  --ctlog-threshold=<value>  [default: 1] number of certificate transparency log entries required to verify
  --tlog-threshold=<value>   [default: 1] number of transparency log entries required to verify

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  verify the supplied .sigstore bundle file

EXAMPLES
  $ sigstore verify ./bundle.sigstore
```


<!-- commandsstop -->
