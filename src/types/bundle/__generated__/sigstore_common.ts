/* eslint-disable */
import { Timestamp } from "./google/protobuf/timestamp";

/**
 * Only a subset of the secure hash standard algorithms are supported.
 * See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf> for more
 * details.
 * UNSPECIFIED SHOULD not be used, primary reason for inclusion is to force
 * any proto JSON serialization to emit the used hash algorithm, as default
 * option is to *omit* the default value of an enum (which is the first
 * value, represented by '0'.
 */
export enum HashAlgorithm {
  HASH_ALGORITHM_UNSPECIFIED = 0,
  SHA2_256 = 1,
}

export function hashAlgorithmFromJSON(object: any): HashAlgorithm {
  switch (object) {
    case 0:
    case "HASH_ALGORITHM_UNSPECIFIED":
      return HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED;
    case 1:
    case "SHA2_256":
      return HashAlgorithm.SHA2_256;
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
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum HashAlgorithm");
  }
}

/**
 * Details of a specific public key, capturing the the key encoding method,
 * and signature algorithm.
 * To avoid the possibility of contradicting formats such as PKCS1 with
 * ED25519 the valid permutations are listed as a linear set instead of a
 * cartesian set (i.e one combined variable instead of two, one for encoding
 * and one for the signature algorithm).
 */
export enum PublicKeyDetails {
  PUBLIC_KEY_DETAILS_UNSPECIFIED = 0,
  /** PKCS1_RSA_PKCS1V5 - RSA */
  PKCS1_RSA_PKCS1V5 = 1,
  /** PKCS1_RSA_PSS - See RFC8017 */
  PKCS1_RSA_PSS = 2,
  PKIX_RSA_PKCS1V5 = 3,
  PKIX_RSA_PSS = 4,
  /** PKIX_ECDSA_P256_SHA_256 - ECDSA */
  PKIX_ECDSA_P256_SHA_256 = 5,
  /** PKIX_ECDSA_P256_HMAC_SHA_256 - See RFC6979 */
  PKIX_ECDSA_P256_HMAC_SHA_256 = 6,
  /** PKIX_ED25519 - Ed 25519 */
  PKIX_ED25519 = 7,
}

export function publicKeyDetailsFromJSON(object: any): PublicKeyDetails {
  switch (object) {
    case 0:
    case "PUBLIC_KEY_DETAILS_UNSPECIFIED":
      return PublicKeyDetails.PUBLIC_KEY_DETAILS_UNSPECIFIED;
    case 1:
    case "PKCS1_RSA_PKCS1V5":
      return PublicKeyDetails.PKCS1_RSA_PKCS1V5;
    case 2:
    case "PKCS1_RSA_PSS":
      return PublicKeyDetails.PKCS1_RSA_PSS;
    case 3:
    case "PKIX_RSA_PKCS1V5":
      return PublicKeyDetails.PKIX_RSA_PKCS1V5;
    case 4:
    case "PKIX_RSA_PSS":
      return PublicKeyDetails.PKIX_RSA_PSS;
    case 5:
    case "PKIX_ECDSA_P256_SHA_256":
      return PublicKeyDetails.PKIX_ECDSA_P256_SHA_256;
    case 6:
    case "PKIX_ECDSA_P256_HMAC_SHA_256":
      return PublicKeyDetails.PKIX_ECDSA_P256_HMAC_SHA_256;
    case 7:
    case "PKIX_ED25519":
      return PublicKeyDetails.PKIX_ED25519;
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum PublicKeyDetails");
  }
}

export function publicKeyDetailsToJSON(object: PublicKeyDetails): string {
  switch (object) {
    case PublicKeyDetails.PUBLIC_KEY_DETAILS_UNSPECIFIED:
      return "PUBLIC_KEY_DETAILS_UNSPECIFIED";
    case PublicKeyDetails.PKCS1_RSA_PKCS1V5:
      return "PKCS1_RSA_PKCS1V5";
    case PublicKeyDetails.PKCS1_RSA_PSS:
      return "PKCS1_RSA_PSS";
    case PublicKeyDetails.PKIX_RSA_PKCS1V5:
      return "PKIX_RSA_PKCS1V5";
    case PublicKeyDetails.PKIX_RSA_PSS:
      return "PKIX_RSA_PSS";
    case PublicKeyDetails.PKIX_ECDSA_P256_SHA_256:
      return "PKIX_ECDSA_P256_SHA_256";
    case PublicKeyDetails.PKIX_ECDSA_P256_HMAC_SHA_256:
      return "PKIX_ECDSA_P256_HMAC_SHA_256";
    case PublicKeyDetails.PKIX_ED25519:
      return "PKIX_ED25519";
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum PublicKeyDetails");
  }
}

export enum SubjectAlternativeNameType {
  SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED = 0,
  EMAIL = 1,
  URI = 2,
  /**
   * OTHER_NAME - OID 1.3.6.1.4.1.57264.1.7
   * See https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726417--othername-san
   * for more details.
   */
  OTHER_NAME = 3,
}

export function subjectAlternativeNameTypeFromJSON(object: any): SubjectAlternativeNameType {
  switch (object) {
    case 0:
    case "SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED":
      return SubjectAlternativeNameType.SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED;
    case 1:
    case "EMAIL":
      return SubjectAlternativeNameType.EMAIL;
    case 2:
    case "URI":
      return SubjectAlternativeNameType.URI;
    case 3:
    case "OTHER_NAME":
      return SubjectAlternativeNameType.OTHER_NAME;
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum SubjectAlternativeNameType");
  }
}

export function subjectAlternativeNameTypeToJSON(object: SubjectAlternativeNameType): string {
  switch (object) {
    case SubjectAlternativeNameType.SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED:
      return "SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED";
    case SubjectAlternativeNameType.EMAIL:
      return "EMAIL";
    case SubjectAlternativeNameType.URI:
      return "URI";
    case SubjectAlternativeNameType.OTHER_NAME:
      return "OTHER_NAME";
    default:
      throw new globalThis.Error("Unrecognized enum value " + object + " for enum SubjectAlternativeNameType");
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

/** LogId captures the identity of a transparency log. */
export interface LogId {
  /**
   * The unique id of the log, represented as the SHA-256 hash
   * of the log's public key, computed over the DER encoding.
   * <https://www.rfc-editor.org/rfc/rfc6962#section-3.2>
   */
  keyId: Buffer;
}

/** This message holds a RFC 3161 timestamp. */
export interface RFC3161SignedTimestamp {
  /**
   * Signed timestamp is the DER encoded TimeStampResponse.
   * See https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2
   */
  signedTimestamp: Buffer;
}

export interface PublicKey {
  /**
   * DER-encoded public key, encoding method is specified by the
   * key_details attribute.
   */
  rawBytes?:
    | Buffer
    | undefined;
  /** Key encoding and signature algorithm to use for this key. */
  keyDetails: PublicKeyDetails;
  /** Optional validity period for this key. */
  validFor?: TimeRange | undefined;
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
   * Implementors are RECOMMENDED to derive the value from the public
   * key as described in RFC 6962.
   * See: <https://www.rfc-editor.org/rfc/rfc6962#section-3.2>
   */
  hint: string;
}

/** An ASN.1 OBJECT IDENTIFIER */
export interface ObjectIdentifier {
  id: number[];
}

/** An OID and the corresponding (byte) value. */
export interface ObjectIdentifierValuePair {
  oid: ObjectIdentifier | undefined;
  value: Buffer;
}

export interface DistinguishedName {
  organization: string;
  commonName: string;
}

export interface X509Certificate {
  /** DER-encoded X.509 certificate. */
  rawBytes: Buffer;
}

export interface SubjectAlternativeName {
  type: SubjectAlternativeNameType;
  identity?: { $case: "regexp"; regexp: string } | { $case: "value"; value: string };
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
 * The time range is half-open and does not include the end timestamp,
 * i.e [start, end).
 * End is optional to be able to capture a period that has started but
 * has no known end.
 */
export interface TimeRange {
  start: Date | undefined;
  end?: Date | undefined;
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

function createBaseLogId(): LogId {
  return { keyId: Buffer.alloc(0) };
}

export const LogId = {
  fromJSON(object: any): LogId {
    return { keyId: isSet(object.keyId) ? Buffer.from(bytesFromBase64(object.keyId)) : Buffer.alloc(0) };
  },

  toJSON(message: LogId): unknown {
    const obj: any = {};
    message.keyId !== undefined &&
      (obj.keyId = base64FromBytes(message.keyId !== undefined ? message.keyId : Buffer.alloc(0)));
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

function createBasePublicKey(): PublicKey {
  return { rawBytes: undefined, keyDetails: 0, validFor: undefined };
}

export const PublicKey = {
  fromJSON(object: any): PublicKey {
    return {
      rawBytes: isSet(object.rawBytes) ? Buffer.from(bytesFromBase64(object.rawBytes)) : undefined,
      keyDetails: isSet(object.keyDetails) ? publicKeyDetailsFromJSON(object.keyDetails) : 0,
      validFor: isSet(object.validFor) ? TimeRange.fromJSON(object.validFor) : undefined,
    };
  },

  toJSON(message: PublicKey): unknown {
    const obj: any = {};
    message.rawBytes !== undefined &&
      (obj.rawBytes = message.rawBytes !== undefined ? base64FromBytes(message.rawBytes) : undefined);
    message.keyDetails !== undefined && (obj.keyDetails = publicKeyDetailsToJSON(message.keyDetails));
    message.validFor !== undefined &&
      (obj.validFor = message.validFor ? TimeRange.toJSON(message.validFor) : undefined);
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

function createBaseObjectIdentifier(): ObjectIdentifier {
  return { id: [] };
}

export const ObjectIdentifier = {
  fromJSON(object: any): ObjectIdentifier {
    return { id: Array.isArray(object?.id) ? object.id.map((e: any) => Number(e)) : [] };
  },

  toJSON(message: ObjectIdentifier): unknown {
    const obj: any = {};
    if (message.id) {
      obj.id = message.id.map((e) => Math.round(e));
    } else {
      obj.id = [];
    }
    return obj;
  },
};

function createBaseObjectIdentifierValuePair(): ObjectIdentifierValuePair {
  return { oid: undefined, value: Buffer.alloc(0) };
}

export const ObjectIdentifierValuePair = {
  fromJSON(object: any): ObjectIdentifierValuePair {
    return {
      oid: isSet(object.oid) ? ObjectIdentifier.fromJSON(object.oid) : undefined,
      value: isSet(object.value) ? Buffer.from(bytesFromBase64(object.value)) : Buffer.alloc(0),
    };
  },

  toJSON(message: ObjectIdentifierValuePair): unknown {
    const obj: any = {};
    message.oid !== undefined && (obj.oid = message.oid ? ObjectIdentifier.toJSON(message.oid) : undefined);
    message.value !== undefined &&
      (obj.value = base64FromBytes(message.value !== undefined ? message.value : Buffer.alloc(0)));
    return obj;
  },
};

function createBaseDistinguishedName(): DistinguishedName {
  return { organization: "", commonName: "" };
}

export const DistinguishedName = {
  fromJSON(object: any): DistinguishedName {
    return {
      organization: isSet(object.organization) ? String(object.organization) : "",
      commonName: isSet(object.commonName) ? String(object.commonName) : "",
    };
  },

  toJSON(message: DistinguishedName): unknown {
    const obj: any = {};
    message.organization !== undefined && (obj.organization = message.organization);
    message.commonName !== undefined && (obj.commonName = message.commonName);
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

function createBaseSubjectAlternativeName(): SubjectAlternativeName {
  return { type: 0, identity: undefined };
}

export const SubjectAlternativeName = {
  fromJSON(object: any): SubjectAlternativeName {
    return {
      type: isSet(object.type) ? subjectAlternativeNameTypeFromJSON(object.type) : 0,
      identity: isSet(object.regexp)
        ? { $case: "regexp", regexp: String(object.regexp) }
        : isSet(object.value)
        ? { $case: "value", value: String(object.value) }
        : undefined,
    };
  },

  toJSON(message: SubjectAlternativeName): unknown {
    const obj: any = {};
    message.type !== undefined && (obj.type = subjectAlternativeNameTypeToJSON(message.type));
    message.identity?.$case === "regexp" && (obj.regexp = message.identity?.regexp);
    message.identity?.$case === "value" && (obj.value = message.identity?.value);
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

function createBaseTimeRange(): TimeRange {
  return { start: undefined, end: undefined };
}

export const TimeRange = {
  fromJSON(object: any): TimeRange {
    return {
      start: isSet(object.start) ? fromJsonTimestamp(object.start) : undefined,
      end: isSet(object.end) ? fromJsonTimestamp(object.end) : undefined,
    };
  },

  toJSON(message: TimeRange): unknown {
    const obj: any = {};
    message.start !== undefined && (obj.start = message.start.toISOString());
    message.end !== undefined && (obj.end = message.end.toISOString());
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

function fromTimestamp(t: Timestamp): Date {
  let millis = Number(t.seconds) * 1_000;
  millis += t.nanos / 1_000_000;
  return new Date(millis);
}

function fromJsonTimestamp(o: any): Date {
  if (o instanceof Date) {
    return o;
  } else if (typeof o === "string") {
    return new Date(o);
  } else {
    return fromTimestamp(Timestamp.fromJSON(o));
  }
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
