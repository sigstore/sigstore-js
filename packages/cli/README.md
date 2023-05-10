# @sigstore/cli

CLI for creating and verifying Sigstore bundles.

# Usage
<!-- usage -->
```sh-session
$ npm install -g @sigstore/cli
$ sigstore COMMAND
running command...
$ sigstore (--version)
@sigstore/cli/0.0.1 darwin-arm64 node-v18.12.1
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
* [`sigstore verify BUNDLE`](#sigstore-verify-bundle)

## `sigstore attest FILE`

attest the supplied file

```
USAGE
  $ sigstore attest FILE [--json] [--fulcio-url <value>] [--rekor-url <value>] [--tsa-server-url <value>]
    [--tlog-upload] [--oidc-client-id <value>] [--oidc-issuer <value>] [--oidc-redirect-url <value>] [-t <value>] [-o
    <value>]

ARGUMENTS
  FILE  file to attest

FLAGS
  -o, --output-file=<value>    write output to file
  -t, --type=<value>           [default: application/vnd.in-toto+json] type to apply to the DSSE envelope
  --fulcio-url=<value>         [default: https://fulcio.sigstore.dev] URL to the Sigstore PKI server
  --oidc-client-id=<value>     [default: sigstore] OIDC client ID for application
  --oidc-issuer=<value>        [default: https://oauth2.sigstore.dev/auth] OIDC provider to be used to issue ID token
  --oidc-redirect-url=<value>  OIDC redirect URL
  --rekor-url=<value>          [default: https://rekor.sigstore.dev] URL to the Rekor transparency log
  --tlog-upload                whether or not to upload entry to the transparency log
  --tsa-server-url=<value>     URL to the Timestamping Authority

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  attest the supplied file

EXAMPLES
  $ sigstore attest
```

_See code: [dist/commands/attest.ts](https://github.com/sigstore/sigstore-js/blob/v0.0.1/dist/commands/attest.ts)_

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

_See code: [@oclif/plugin-help](https://github.com/oclif/plugin-help/blob/v5.2.9/src/commands/help.ts)_

## `sigstore verify BUNDLE`

describe the command here

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
  describe the command here

EXAMPLES
  $ sigstore verify
```

_See code: [dist/commands/verify.ts](https://github.com/sigstore/sigstore-js/blob/v0.0.1/dist/commands/verify.ts)_
<!-- commandsstop -->
