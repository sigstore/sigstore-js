export class VerificationError extends Error {}

export class InvalidBundleError extends Error {}

export class UnsupportedVersionError extends Error {}

export class CertificateChainVerificationError extends VerificationError {}
