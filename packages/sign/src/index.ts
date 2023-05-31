export type { Bundle } from '@sigstore/bundle';
export { InternalError } from './error';
export { CIContextProvider } from './identity';
export type { IdentityProvider } from './identity';
export { DSSENotary, MessageNotary } from './notary';
export type { Artifact, Notary, NotaryOptions } from './notary';
export { FulcioSigner } from './signatory';
export type { Endorsement, FulcioSignerOptions, Signatory } from './signatory';
export { RekorWitness, TSAWitness } from './witness';
export type {
  Affidavit,
  RekorWitnessOptions,
  SignatureBundle,
  TSAWitnessOptions,
  Witness,
} from './witness';
