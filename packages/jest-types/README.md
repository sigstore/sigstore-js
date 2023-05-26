# @types/sigstore-jest-extended

TypeScript types for the custom Jest `Matcher` extensions used
in the `sigstore` package. This is a private package and is
not published to the registry.

We're using the fact that typescript will automatically load
types for any package in the `@types` namespace to have the
definitions for our custom matchers merged into the global
`jest` namespace automatically.
