/* eslint-disable */

/**
 * Only a subset of the secure hash standard algorithms are supported.
 * See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for more
 * details.
 * UNSPECIFIED SHOULD not be used, primary reason for inclusion is to force
 * any proto JSON serialization to emit the used hash algorithm, as default
 * option is to *omit* the default value of an emum (which is the first
 * value, represented by '0'.
 */
export enum HashAlgorithm {
  HASH_ALGORITHM_UNSPECIFIED = 0,
  SHA2_256 = 1,
  SHA2_512 = 2,
}

export function hashAlgorithmFromJSON(object: any): HashAlgorithm {
  switch (object) {
    case 0:
    case "HASH_ALGORITHM_UNSPECIFIED":
      return HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED;
    case 1:
    case "SHA2_256":
      return HashAlgorithm.SHA2_256;
    case 2:
    case "SHA2_512":
      return HashAlgorithm.SHA2_512;
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum HashAlgorithm");
  }
}

export function hashAlgorithmToJSON(object: HashAlgorithm): string {
  switch (object) {
    case HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED:
      return "HASH_ALGORITHM_UNSPECIFIED";
    case HashAlgorithm.SHA2_256:
      return "SHA2_256";
    case HashAlgorithm.SHA2_512:
      return "SHA2_512";
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum HashAlgorithm");
  }
}

/**
 * HashOutput captures a digest of a 'message' (generic octet sequence)
 * and the corresponding hash algorithm used.
 */
export interface HashOutput {
  algorithm: HashAlgorithm;
  /**
   * This is the raw octets of the message digest as computed by
   * the hash algorithm.
   */
  digest: Buffer;
}

/** MessageSignature stores the computed signature over a message. */
export interface MessageSignature {
  /** Message digest can be used to identify the artifact. */
  messageDigest:
    | HashOutput
    | undefined;
  /**
   * The raw bytes as returned from the signature algorithm.
   * The signature algorithm (and so the format of the signature bytes)
   * are determined by the contents of the 'verification_material',
   * either a key-pair or a certificate. If using a certificate, the
   * certificate contains the required information on the signature
   * algorithm.
   * When using a key pair, the algorithm MUST be part of the public
   * key, which MUST be communicated out-of-band.
   */
  signature: Buffer;
}

/** This message holds a RFC 3161 timestamp. */
export interface RFC3161SignedTimestamp {
  /**
   * Signed timestamp is the DER encoded TimeStampResponse.
   * See https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2
   */
  signedTimestamp: Buffer;
}

/**
 * PublicKeyIdentifier can be used to identify an (out of band) delivered
 * key, to verify a signature.
 */
export interface PublicKeyIdentifier {
  /**
   * Optional unauthenticated hint on which key to use.
   * The format of the hint must be agreed upon out of band by the
   * signer and the verifiers, and so is not subject to this
   * specification.
   * Example use-case is to specify the public key to use, from a
   * trusted key-ring.
   * Implementors are RECOMMENDED derive the value from the public
   * key as described in https://www.rfc-editor.org/rfc/rfc3280#section-4.2.1.1
   */
  hint: string;
}

export interface X509Certificate {
  /** DER-encoded X.509 certificate. */
  rawBytes: Buffer;
}

/** A chain of X.509 certificates. */
export interface X509CertificateChain {
  /**
   * The chain of certificates, with indices 0 to n.
   * The first certificate in the array must be the leaf
   * certificate used for signing. Any intermediate certificates
   * must be stored as offset 1 to n-1, and the root certificate at
   * position n.
   */
  certificates: X509Certificate[];
}

/**
 * VerificationMaterial captures details on the materials used to verify
 * signatures.
 */
export interface VerificationMaterial {
  content?: { $case: "publicKey"; publicKey: PublicKeyIdentifier } | {
    $case: "x509CertificateChain";
    x509CertificateChain: X509CertificateChain;
  };
}

function createBaseHashOutput(): HashOutput {
  return { algorithm: 0, digest: Buffer.alloc(0) };
}

export const HashOutput = {
  fromJSON(object: any): HashOutput {
    return {
      algorithm: isSet(object.algorithm) ? hashAlgorithmFromJSON(object.algorithm) : 0,
      digest: isSet(object.digest) ? Buffer.from(bytesFromBase64(object.digest)) : Buffer.alloc(0),
    };
  },

  toJSON(message: HashOutput): unknown {
    const obj: any = {};
    message.algorithm !== undefined && (obj.algorithm = hashAlgorithmToJSON(message.algorithm));
    message.digest !== undefined &&
      (obj.digest = base64FromBytes(message.digest !== undefined ? message.digest : Buffer.alloc(0)));
    return obj;
  },
};

function createBaseMessageSignature(): MessageSignature {
  return { messageDigest: undefined, signature: Buffer.alloc(0) };
}

export const MessageSignature = {
  fromJSON(object: any): MessageSignature {
    return {
      messageDigest: isSet(object.messageDigest) ? HashOutput.fromJSON(object.messageDigest) : undefined,
      signature: isSet(object.signature) ? Buffer.from(bytesFromBase64(object.signature)) : Buffer.alloc(0),
    };
  },

  toJSON(message: MessageSignature): unknown {
    const obj: any = {};
    message.messageDigest !== undefined &&
      (obj.messageDigest = message.messageDigest ? HashOutput.toJSON(message.messageDigest) : undefined);
    message.signature !== undefined &&
      (obj.signature = base64FromBytes(message.signature !== undefined ? message.signature : Buffer.alloc(0)));
    return obj;
  },
};

function createBaseRFC3161SignedTimestamp(): RFC3161SignedTimestamp {
  return { signedTimestamp: Buffer.alloc(0) };
}

export const RFC3161SignedTimestamp = {
  fromJSON(object: any): RFC3161SignedTimestamp {
    return {
      signedTimestamp: isSet(object.signedTimestamp)
        ? Buffer.from(bytesFromBase64(object.signedTimestamp))
        : Buffer.alloc(0),
    };
  },

  toJSON(message: RFC3161SignedTimestamp): unknown {
    const obj: any = {};
    message.signedTimestamp !== undefined &&
      (obj.signedTimestamp = base64FromBytes(
        message.signedTimestamp !== undefined ? message.signedTimestamp : Buffer.alloc(0),
      ));
    return obj;
  },
};

function createBasePublicKeyIdentifier(): PublicKeyIdentifier {
  return { hint: "" };
}

export const PublicKeyIdentifier = {
  fromJSON(object: any): PublicKeyIdentifier {
    return { hint: isSet(object.hint) ? String(object.hint) : "" };
  },

  toJSON(message: PublicKeyIdentifier): unknown {
    const obj: any = {};
    message.hint !== undefined && (obj.hint = message.hint);
    return obj;
  },
};

function createBaseX509Certificate(): X509Certificate {
  return { rawBytes: Buffer.alloc(0) };
}

export const X509Certificate = {
  fromJSON(object: any): X509Certificate {
    return { rawBytes: isSet(object.rawBytes) ? Buffer.from(bytesFromBase64(object.rawBytes)) : Buffer.alloc(0) };
  },

  toJSON(message: X509Certificate): unknown {
    const obj: any = {};
    message.rawBytes !== undefined &&
      (obj.rawBytes = base64FromBytes(message.rawBytes !== undefined ? message.rawBytes : Buffer.alloc(0)));
    return obj;
  },
};

function createBaseX509CertificateChain(): X509CertificateChain {
  return { certificates: [] };
}

export const X509CertificateChain = {
  fromJSON(object: any): X509CertificateChain {
    return {
      certificates: Array.isArray(object?.certificates)
        ? object.certificates.map((e: any) => X509Certificate.fromJSON(e))
        : [],
    };
  },

  toJSON(message: X509CertificateChain): unknown {
    const obj: any = {};
    if (message.certificates) {
      obj.certificates = message.certificates.map((e) => e ? X509Certificate.toJSON(e) : undefined);
    } else {
      obj.certificates = [];
    }
    return obj;
  },
};

function createBaseVerificationMaterial(): VerificationMaterial {
  return { content: undefined };
}

export const VerificationMaterial = {
  fromJSON(object: any): VerificationMaterial {
    return {
      content: isSet(object.publicKey)
        ? { $case: "publicKey", publicKey: PublicKeyIdentifier.fromJSON(object.publicKey) }
        : isSet(object.x509CertificateChain)
        ? {
          $case: "x509CertificateChain",
          x509CertificateChain: X509CertificateChain.fromJSON(object.x509CertificateChain),
        }
        : undefined,
    };
  },

  toJSON(message: VerificationMaterial): unknown {
    const obj: any = {};
    message.content?.$case === "publicKey" &&
      (obj.publicKey = message.content?.publicKey ? PublicKeyIdentifier.toJSON(message.content?.publicKey) : undefined);
    message.content?.$case === "x509CertificateChain" &&
      (obj.x509CertificateChain = message.content?.x509CertificateChain
        ? X509CertificateChain.toJSON(message.content?.x509CertificateChain)
        : undefined);
    return obj;
  },
};

declare var self: any | undefined;
declare var window: any | undefined;
declare var global: any | undefined;
var globalThis: any = (() => {
  if (typeof globalThis !== "undefined") {
    return globalThis;
  }
  if (typeof self !== "undefined") {
    return self;
  }
  if (typeof window !== "undefined") {
    return window;
  }
  if (typeof global !== "undefined") {
    return global;
  }
  throw "Unable to locate global object";
})();

function bytesFromBase64(b64: string): Uint8Array {
  if (globalThis.Buffer) {
    return Uint8Array.from(globalThis.Buffer.from(b64, "base64"));
  } else {
    const bin = globalThis.atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; ++i) {
      arr[i] = bin.charCodeAt(i);
    }
    return arr;
  }
}

function base64FromBytes(arr: Uint8Array): string {
  if (globalThis.Buffer) {
    return globalThis.Buffer.from(arr).toString("base64");
  } else {
    const bin: string[] = [];
    arr.forEach((byte) => {
      bin.push(String.fromCharCode(byte));
    });
    return globalThis.btoa(bin.join(""));
  }
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
