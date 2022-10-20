// Serialized form of the verificationData in the Sigstore Bundle
type SerializedVerificationData = {
  tlogEntries: {
    logIndex: string;
    logId: {
      keyId: string;
    };
    kindVersion:
      | {
          kind: string;
          version: string;
        }
      | undefined;
    integratedTime: string;
    inclusionPromise: {
      signedEntryTimestamp: string;
    };
    inclusionProof:
      | {
          logIndex: string;
          rootHash: string;
          treeSize: string;
          hashes: string[];
          checkpoint: { envelope: string };
        }
      | undefined;
  }[];
  timestampVerificationData: {
    rfc3161Timestamps: { signedTimestamp: string }[];
  };
};

// Serialized form of the x509CertificateChain option in the Sigstore Bundle's
// verificationMaterial
type Serializedx509CertificateChain = {
  x509CertificateChain: {
    certificates: { derBytes: string }[];
  };
};

// Serialized form of the publicKey option in the Sigstore Bundle's
// verificationMaterial
type SerializedPublicKey = { publicKey: { hint: string } };

// Serialized form of the messageSignature option in the Sigstore Bundle
type SerializedMessageSignature = {
  messageSignature: {
    messageDigest:
      | {
          algorithm: string;
          digest: string;
        }
      | undefined;
    signature: string;
  };
};

// Serialized form of the dsseEnvelope option in the Sigstore Bundle
type SerializedDSSEEnvelope = {
  dsseEnvelope: {
    payload: string;
    payloadType: string;
    signatures: {
      sig: string;
      keyid: string;
    }[];
  };
};

// Serialized form of the Sigstore Bundle union type with all possible options
// represented
export type SerializedBundle = {
  mediaType: string;
  verificationData: SerializedVerificationData | undefined;
  verificationMaterial:
    | Serializedx509CertificateChain
    | SerializedPublicKey
    | undefined;
} & (SerializedMessageSignature | SerializedDSSEEnvelope);

// Serialized form of the Sigstore Bundle with dsseEnvelope and
// x509CertificateChain options
export type SerializedDSSEBundle = {
  mediaType: string;
  verificationData: SerializedVerificationData | undefined;
  verificationMaterial: Serializedx509CertificateChain | undefined;
} & SerializedDSSEEnvelope;

// Serialized form of the Sigstore Bundle with messageSignature and
// x509CertificateChain options
export type SerializedMessageSignatureBundle = {
  mediaType: string;
  verificationData: SerializedVerificationData | undefined;
  verificationMaterial: Serializedx509CertificateChain | undefined;
} & SerializedMessageSignature;
