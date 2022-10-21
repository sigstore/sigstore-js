import { OneOf } from './utility';

interface VerificationMaterial {
  certificates: string[];
  key: {
    id?: string;
    value: string;
  };
}

// Result of signing some artifact. Containing the signature and either the
// signing certificate chain or the public key.
export type SignatureMaterial = {
  signature: Buffer;
} & OneOf<VerificationMaterial>;

export type SignerFunc = (payload: Buffer) => Promise<SignatureMaterial>;
