/* eslint-disable */
import { Envelope } from "./envelope";

/**
 * Only a subset of the secure hash standard algorithms are supported.
 * See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for more
 * details.
 */
export enum HashAlgorithm {
  SHA2_256 = 0,
  SHA2_512 = 1,
}

export function hashAlgorithmFromJSON(object: any): HashAlgorithm {
  switch (object) {
    case 0:
    case "SHA2_256":
      return HashAlgorithm.SHA2_256;
    case 1:
    case "SHA2_512":
      return HashAlgorithm.SHA2_512;
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum HashAlgorithm");
  }
}

export function hashAlgorithmToJSON(object: HashAlgorithm): string {
  switch (object) {
    case HashAlgorithm.SHA2_256:
      return "SHA2_256";
    case HashAlgorithm.SHA2_512:
      return "SHA2_512";
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum HashAlgorithm");
  }
}

/**
 * HashOutput captures a digest of a 'message' and the corresponding hash
 * algorithm used.
 */
export interface HashOutput {
  algorithm: HashAlgorithm;
  /**
   * This is the raw octets of the message digest as computed by
   * the hash algorithm.
   */
  digest: Buffer;
}

/**
 * MessageSignature stores the computed signature over a message's (generic
 * octet sequence) digest.
 */
export interface MessageSignature {
  payloadDigest: HashOutput | undefined;
  signature: Buffer;
}

/** RekorKindVersion contains the entry's kind and api version. */
export interface RekorKindVersion {
  /**
   * Kind is the type of entry being stored in the log.
   * See here for a list: https://github.com/sigstore/rekor/tree/main/pkg/types
   */
  kind: string;
  /** The specific api version of the type. */
  version: string;
}

/**
 * InclusionProof is the proof returned from the transparency log. Can
 * be used for on line verification against the log.
 */
export interface InclusionProof {
  /** The index of the entry in the log. */
  logIndex: string;
  /**
   * The hash value stored at the root of the merkle tree at the time
   * the proof was generated, hex encoded.
   */
  rootHash: string;
  /** The size of the merkle tree at the time the proof was generated. */
  treeSize: string;
  /**
   * A list of hashes required to compute the inclusion proof, sorted
   * in order from leaf to root. Each hash value is hex encoded.
   */
  hashes: string[];
  /**
   * The signed tree head that the inclusion proof is based on. The
   * signature is base64 encoded.
   */
  checkpoint: string;
}

/**
 * TransparencyLogEntry is a separate type, capturing all the details required
 * from Rekor to reconstruct an entry, given that the payload is provided
 * via other means.
 * This type can easily be created from the existing response from Rekor.
 * Future iterations could rely on Rekor returning the minimal set of
 * attributes (excluding the payload) that are required for verifying the
 * inclusion promise. The inclusion promise (called SignedEntryTimestamp
 * the response from Rekor) is similar to a Signed Certificate Timestamp
 * as described here https://www.rfc-editor.org/rfc/rfc9162#name-signed-certificate-timestam.
 */
export interface TransparencyLogEntry {
  /** The index of the entry in the log. */
  logIndex: string;
  /** The unique (binary) identifier of the log, as a hex-encoded string. */
  logId: string;
  /**
   * Even if kind can be derived from the attestation type it's kept
   * as this struct could be automatically created by the sigstore
   * library based on the response from Rekor. Also during verification
   * this struct can be passed to the library for Rekor entry
   * reconstruction. By duplicating the kind here we would so minimize
   * any possibility of error due to attestation/kind matching logic,
   * as that logic must be hard-coded in the client. With this construct
   * it's only determined during publish to Rekor.
   */
  kindVersion:
    | RekorKindVersion
    | undefined;
  /** The UNIX timestamp from the log when the entry was persisted. */
  integratedTime: string;
  /**
   * The inclusion promise is calculated by Rekor. It's calculated as a
   * signature over the persisted entry, the log ID, log index and the
   * integration timestamp. The signature is base64 encoded.
   * This is primarily used to verify the
   * integration timestamp's value.
   */
  inclusionPromise: string;
  /**
   * The inclusion proof can be used for online verification that the
   * entry was appended to the log, and that the log has not been
   * altered.
   */
  inclusionProof: InclusionProof | undefined;
}

/** A list of base64 encoded RFC3161 signed timestamps. */
export interface SignedTimestamps {
  signedTimestamps: string[];
}

/**
 * This message contains the transparency log entry (inclusion promise and
 * proof) and signed timestamps, provided by sigstore and/or the user.
 */
export interface TimestampedTransparencyLogEntry {
  tlogEntry: TransparencyLogEntry | undefined;
  timestamps: SignedTimestamps | undefined;
}

export interface VerificationData {
  data?: { $case: "tlogEntry"; tlogEntry: TransparencyLogEntry } | {
    $case: "timestampedTlogEntry";
    timestampedTlogEntry: TimestampedTransparencyLogEntry;
  } | { $case: "timestamps"; timestamps: SignedTimestamps };
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
   */
  hint: string;
}

export interface X509Certificate {
  /**
   * PEM encoded certificate(s), with indices 0 to n.
   * For information on PEM encoding, see
   * https://www.rfc-editor.org/rfc/rfc7468#section-2.
   * The first certificate in the array
   * must be the leaf certificate used for signing. Any intermediate
   * certificates must be stored as offset 1 to n-1, and the root
   * certificate at position n.
   */
  certificates: string[];
}

export interface Bundle {
  /**
   * MUST be application/vnd.dev.sigstore.bundle.v0.1+json
   * when encoded as JSON.
   */
  mediaType: string;
  verificationData?: VerificationData | undefined;
  verificationMaterial?: { $case: "publicKey"; publicKey: PublicKeyIdentifier } | {
    $case: "x509Certificate";
    x509Certificate: X509Certificate;
  };
  attestation?: { $case: "messageSignature"; messageSignature: MessageSignature } | {
    $case: "attestationDsse";
    attestationDsse: Envelope;
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
  return { payloadDigest: undefined, signature: Buffer.alloc(0) };
}

export const MessageSignature = {
  fromJSON(object: any): MessageSignature {
    return {
      payloadDigest: isSet(object.payloadDigest) ? HashOutput.fromJSON(object.payloadDigest) : undefined,
      signature: isSet(object.signature) ? Buffer.from(bytesFromBase64(object.signature)) : Buffer.alloc(0),
    };
  },

  toJSON(message: MessageSignature): unknown {
    const obj: any = {};
    message.payloadDigest !== undefined &&
      (obj.payloadDigest = message.payloadDigest ? HashOutput.toJSON(message.payloadDigest) : undefined);
    message.signature !== undefined &&
      (obj.signature = base64FromBytes(message.signature !== undefined ? message.signature : Buffer.alloc(0)));
    return obj;
  },
};

function createBaseRekorKindVersion(): RekorKindVersion {
  return { kind: "", version: "" };
}

export const RekorKindVersion = {
  fromJSON(object: any): RekorKindVersion {
    return {
      kind: isSet(object.kind) ? String(object.kind) : "",
      version: isSet(object.version) ? String(object.version) : "",
    };
  },

  toJSON(message: RekorKindVersion): unknown {
    const obj: any = {};
    message.kind !== undefined && (obj.kind = message.kind);
    message.version !== undefined && (obj.version = message.version);
    return obj;
  },
};

function createBaseInclusionProof(): InclusionProof {
  return { logIndex: "0", rootHash: "", treeSize: "0", hashes: [], checkpoint: "" };
}

export const InclusionProof = {
  fromJSON(object: any): InclusionProof {
    return {
      logIndex: isSet(object.logIndex) ? String(object.logIndex) : "0",
      rootHash: isSet(object.rootHash) ? String(object.rootHash) : "",
      treeSize: isSet(object.treeSize) ? String(object.treeSize) : "0",
      hashes: Array.isArray(object?.hashes) ? object.hashes.map((e: any) => String(e)) : [],
      checkpoint: isSet(object.checkpoint) ? String(object.checkpoint) : "",
    };
  },

  toJSON(message: InclusionProof): unknown {
    const obj: any = {};
    message.logIndex !== undefined && (obj.logIndex = message.logIndex);
    message.rootHash !== undefined && (obj.rootHash = message.rootHash);
    message.treeSize !== undefined && (obj.treeSize = message.treeSize);
    if (message.hashes) {
      obj.hashes = message.hashes.map((e) => e);
    } else {
      obj.hashes = [];
    }
    message.checkpoint !== undefined && (obj.checkpoint = message.checkpoint);
    return obj;
  },
};

function createBaseTransparencyLogEntry(): TransparencyLogEntry {
  return {
    logIndex: "0",
    logId: "",
    kindVersion: undefined,
    integratedTime: "0",
    inclusionPromise: "",
    inclusionProof: undefined,
  };
}

export const TransparencyLogEntry = {
  fromJSON(object: any): TransparencyLogEntry {
    return {
      logIndex: isSet(object.logIndex) ? String(object.logIndex) : "0",
      logId: isSet(object.logId) ? String(object.logId) : "",
      kindVersion: isSet(object.kindVersion) ? RekorKindVersion.fromJSON(object.kindVersion) : undefined,
      integratedTime: isSet(object.integratedTime) ? String(object.integratedTime) : "0",
      inclusionPromise: isSet(object.inclusionPromise) ? String(object.inclusionPromise) : "",
      inclusionProof: isSet(object.inclusionProof) ? InclusionProof.fromJSON(object.inclusionProof) : undefined,
    };
  },

  toJSON(message: TransparencyLogEntry): unknown {
    const obj: any = {};
    message.logIndex !== undefined && (obj.logIndex = message.logIndex);
    message.logId !== undefined && (obj.logId = message.logId);
    message.kindVersion !== undefined &&
      (obj.kindVersion = message.kindVersion ? RekorKindVersion.toJSON(message.kindVersion) : undefined);
    message.integratedTime !== undefined && (obj.integratedTime = message.integratedTime);
    message.inclusionPromise !== undefined && (obj.inclusionPromise = message.inclusionPromise);
    message.inclusionProof !== undefined &&
      (obj.inclusionProof = message.inclusionProof ? InclusionProof.toJSON(message.inclusionProof) : undefined);
    return obj;
  },
};

function createBaseSignedTimestamps(): SignedTimestamps {
  return { signedTimestamps: [] };
}

export const SignedTimestamps = {
  fromJSON(object: any): SignedTimestamps {
    return {
      signedTimestamps: Array.isArray(object?.signedTimestamps)
        ? object.signedTimestamps.map((e: any) => String(e))
        : [],
    };
  },

  toJSON(message: SignedTimestamps): unknown {
    const obj: any = {};
    if (message.signedTimestamps) {
      obj.signedTimestamps = message.signedTimestamps.map((e) => e);
    } else {
      obj.signedTimestamps = [];
    }
    return obj;
  },
};

function createBaseTimestampedTransparencyLogEntry(): TimestampedTransparencyLogEntry {
  return { tlogEntry: undefined, timestamps: undefined };
}

export const TimestampedTransparencyLogEntry = {
  fromJSON(object: any): TimestampedTransparencyLogEntry {
    return {
      tlogEntry: isSet(object.tlogEntry) ? TransparencyLogEntry.fromJSON(object.tlogEntry) : undefined,
      timestamps: isSet(object.timestamps) ? SignedTimestamps.fromJSON(object.timestamps) : undefined,
    };
  },

  toJSON(message: TimestampedTransparencyLogEntry): unknown {
    const obj: any = {};
    message.tlogEntry !== undefined &&
      (obj.tlogEntry = message.tlogEntry ? TransparencyLogEntry.toJSON(message.tlogEntry) : undefined);
    message.timestamps !== undefined &&
      (obj.timestamps = message.timestamps ? SignedTimestamps.toJSON(message.timestamps) : undefined);
    return obj;
  },
};

function createBaseVerificationData(): VerificationData {
  return { data: undefined };
}

export const VerificationData = {
  fromJSON(object: any): VerificationData {
    return {
      data: isSet(object.tlogEntry)
        ? { $case: "tlogEntry", tlogEntry: TransparencyLogEntry.fromJSON(object.tlogEntry) }
        : isSet(object.timestampedTlogEntry)
        ? {
          $case: "timestampedTlogEntry",
          timestampedTlogEntry: TimestampedTransparencyLogEntry.fromJSON(object.timestampedTlogEntry),
        }
        : isSet(object.timestamps)
        ? { $case: "timestamps", timestamps: SignedTimestamps.fromJSON(object.timestamps) }
        : undefined,
    };
  },

  toJSON(message: VerificationData): unknown {
    const obj: any = {};
    message.data?.$case === "tlogEntry" &&
      (obj.tlogEntry = message.data?.tlogEntry ? TransparencyLogEntry.toJSON(message.data?.tlogEntry) : undefined);
    message.data?.$case === "timestampedTlogEntry" && (obj.timestampedTlogEntry = message.data?.timestampedTlogEntry
      ? TimestampedTransparencyLogEntry.toJSON(message.data?.timestampedTlogEntry)
      : undefined);
    message.data?.$case === "timestamps" &&
      (obj.timestamps = message.data?.timestamps ? SignedTimestamps.toJSON(message.data?.timestamps) : undefined);
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
  return { certificates: [] };
}

export const X509Certificate = {
  fromJSON(object: any): X509Certificate {
    return { certificates: Array.isArray(object?.certificates) ? object.certificates.map((e: any) => String(e)) : [] };
  },

  toJSON(message: X509Certificate): unknown {
    const obj: any = {};
    if (message.certificates) {
      obj.certificates = message.certificates.map((e) => e);
    } else {
      obj.certificates = [];
    }
    return obj;
  },
};

function createBaseBundle(): Bundle {
  return { mediaType: "", verificationData: undefined, verificationMaterial: undefined, attestation: undefined };
}

export const Bundle = {
  fromJSON(object: any): Bundle {
    return {
      mediaType: isSet(object.mediaType) ? String(object.mediaType) : "",
      verificationData: isSet(object.verificationData) ? VerificationData.fromJSON(object.verificationData) : undefined,
      verificationMaterial: isSet(object.publicKey)
        ? { $case: "publicKey", publicKey: PublicKeyIdentifier.fromJSON(object.publicKey) }
        : isSet(object.x509Certificate)
        ? { $case: "x509Certificate", x509Certificate: X509Certificate.fromJSON(object.x509Certificate) }
        : undefined,
      attestation: isSet(object.messageSignature)
        ? { $case: "messageSignature", messageSignature: MessageSignature.fromJSON(object.messageSignature) }
        : isSet(object.attestationDsse)
        ? { $case: "attestationDsse", attestationDsse: Envelope.fromJSON(object.attestationDsse) }
        : undefined,
    };
  },

  toJSON(message: Bundle): unknown {
    const obj: any = {};
    message.mediaType !== undefined && (obj.mediaType = message.mediaType);
    message.verificationData !== undefined &&
      (obj.verificationData = message.verificationData ? VerificationData.toJSON(message.verificationData) : undefined);
    message.verificationMaterial?.$case === "publicKey" && (obj.publicKey = message.verificationMaterial?.publicKey
      ? PublicKeyIdentifier.toJSON(message.verificationMaterial?.publicKey)
      : undefined);
    message.verificationMaterial?.$case === "x509Certificate" &&
      (obj.x509Certificate = message.verificationMaterial?.x509Certificate
        ? X509Certificate.toJSON(message.verificationMaterial?.x509Certificate)
        : undefined);
    message.attestation?.$case === "messageSignature" && (obj.messageSignature = message.attestation?.messageSignature
      ? MessageSignature.toJSON(message.attestation?.messageSignature)
      : undefined);
    message.attestation?.$case === "attestationDsse" && (obj.attestationDsse = message.attestation?.attestationDsse
      ? Envelope.toJSON(message.attestation?.attestationDsse)
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
