# sigstore-js &middot; [![CI Status](https://github.com/sigstore/sigstore-js/workflows/CI/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/ci.yml) [![Smoke Test Status](https://github.com/sigstore/sigstore-js/workflows/smoke-test/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/smoke-test.yml)

JavaScript libraries for interacting with [Sigstore][6] services.

## Packages

* [`sigstore`](./packages/client) - Client library implementing Sigstore signing/verification workflows.
* [`@sigstore/bundle`](./packages/bundle) - TypeScript types and utility functions for working with Sigstore bundles.
* [`@sigstore/cli`](./packages/cli) - Command line interface for signing/verifying artifacts with Sigstore.
* [`@sigstore/tuf`](./packages/tuf) - Library for interacting with the Sigstore TUF repository.
* [`@sigstore/rekor-types`](./packages/rekor-types) - TypeScript types for the Sigstore Rekor REST API.
* [`@sigstore/mock`](./packages/mock) - Mocking library for Sigstore services.

## Development

### Changesets
If you are contributing a user-facing or noteworthy change that should be added to the changelog, you should include a changeset with your PR by running the following command:

```console
npx changeset add
```

Follow the prompts to specify whether the change is a major, minor or patch change. This will create a file in the `.changesets` directory of the repo. This change should be committed and included with your PR.

### Release Steps

Whenever a new changeset is merged to the "main" branch, the `release` workflow will open a PR (or append to the existing PR if one is already open) with the all of the pending changesets.

Publishing a release simply requires that you approve/merge this PR. This will trigger the publishing of the package to the npm registry and the creation of the GitHub release.

## Licensing

`sigstore-js` is licensed under the Apache 2.0 License.

## Contributing

See [the contributing docs][7] for details.

## Code of Conduct
Everyone interacting with this project is expected to follow the [sigstore Code of Conduct][8].

## Security

Should you discover any security issues, please refer to sigstore's [security process][9].

## Info

`sigstore-js` is developed as part of the [`sigstore`][6] project.

We also use a [slack channel][10]! Click [here][11] for the invite link.


[6]: https://sigstore.dev
[7]: https://github.com/sigstore/.github/blob/main/CONTRIBUTING.md
[8]: https://github.com/sigstore/.github/blob/main/CODE_OF_CONDUCT.md
[9]: https://github.com/sigstore/.github/blob/main/SECURITY.md
[10]: https://sigstore.slack.com
[11]: https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ
