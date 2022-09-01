/* eslint-disable */
import { Envelope } from "./envelope";

export enum HashAlgorithm {
  SHA2_224 = 0,
  SHA2_256 = 1,
  SHA2_384 = 2,
  SHA2_512 = 3,
  SHA2_512_224 = 4,
  SHA2_512_256 = 5,
}

export function hashAlgorithmFromJSON(object: any): HashAlgorithm {
  switch (object) {
    case 0:
    case "SHA2_224":
      return HashAlgorithm.SHA2_224;
    case 1:
    case "SHA2_256":
      return HashAlgorithm.SHA2_256;
    case 2:
    case "SHA2_384":
      return HashAlgorithm.SHA2_384;
    case 3:
    case "SHA2_512":
      return HashAlgorithm.SHA2_512;
    case 4:
    case "SHA2_512_224":
      return HashAlgorithm.SHA2_512_224;
    case 5:
    case "SHA2_512_256":
      return HashAlgorithm.SHA2_512_256;
    default:
      throw new globalThis.Error(
        "Unrecognized enum value " + object + " for enum HashAlgorithm"
      );
  }
}

export function hashAlgorithmToJSON(object: HashAlgorithm): string {
  switch (object) {
    case HashAlgorithm.SHA2_224:
      return "SHA2_224";
    case HashAlgorithm.SHA2_256:
      return "SHA2_256";
    case HashAlgorithm.SHA2_384:
      return "SHA2_384";
    case HashAlgorithm.SHA2_512:
      return "SHA2_512";
    case HashAlgorithm.SHA2_512_224:
      return "SHA2_512_224";
    case HashAlgorithm.SHA2_512_256:
      return "SHA2_512_256";
    default:
      throw new globalThis.Error(
        "Unrecognized enum value " + object + " for enum HashAlgorithm"
      );
  }
}

export interface AttestationBlob {
  /** In JSON encoding this shall be base64 encoded. */
  payloadHash: Buffer;
  algorithm: HashAlgorithm;
  /** In JSON encoding this shall be base64 encoded. */
  signature: Buffer;
}

/**
 * RekorEntry is a separate type, capturing all the details required
 * from Rekor to reconstruct an entry, given that the payload is provided
 * via other means.
 * This type can easily be created from the existing response from Rekor.
 * Future iterations could rely on Rekor returning the minimal set of
 * attributes (excluding the payload) that are required for verifying the
 * SET.
 */
export interface RekorEntry {
  logIndex: string;
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
  kind: string;
  version: string;
  signedEntryTimestamp: string;
  /**
   * Note that this will be encoded as a string in JSON:
   * https://developers.google.com/protocol-buffers/docs/proto3#json
   */
  integratedTime: string;
}

export interface PublicKey {
  /**
   * Optional unauthenticated hint on which key to use.
   * If a DSSE envelope is signed, at least one of the signatures
   * MUST have a signature with the same key id.
   */
  keyId: string;
}

export interface X509Cert {
  /** PEM encoded certificate. */
  certificate: string;
  /** PEM encoded certificate chain. */
  chain: string;
}

export interface Bundle {
  /** MUST be application/vnd.dev.sigstore.bundle.v1+json */
  mediaType: string;
  rekorEntry?: RekorEntry | undefined;
  verificationMaterial?:
    | { $case: "publicKey"; publicKey: PublicKey }
    | { $case: "x509Cert"; x509Cert: X509Cert };
  attestation?:
    | { $case: "attestationBlob"; attestationBlob: AttestationBlob }
    | { $case: "attestationDsse"; attestationDsse: Envelope };
}

function createBaseAttestationBlob(): AttestationBlob {
  return {
    payloadHash: Buffer.alloc(0),
    algorithm: 0,
    signature: Buffer.alloc(0),
  };
}

export const AttestationBlob = {
  fromJSON(object: any): AttestationBlob {
    return {
      payloadHash: isSet(object.payloadHash)
        ? Buffer.from(bytesFromBase64(object.payloadHash))
        : Buffer.alloc(0),
      algorithm: isSet(object.algorithm)
        ? hashAlgorithmFromJSON(object.algorithm)
        : 0,
      signature: isSet(object.signature)
        ? Buffer.from(bytesFromBase64(object.signature))
        : Buffer.alloc(0),
    };
  },

  toJSON(message: AttestationBlob): unknown {
    const obj: any = {};
    message.payloadHash !== undefined &&
      (obj.payloadHash = base64FromBytes(
        message.payloadHash !== undefined
          ? message.payloadHash
          : Buffer.alloc(0)
      ));
    message.algorithm !== undefined &&
      (obj.algorithm = hashAlgorithmToJSON(message.algorithm));
    message.signature !== undefined &&
      (obj.signature = base64FromBytes(
        message.signature !== undefined ? message.signature : Buffer.alloc(0)
      ));
    return obj;
  },
};

function createBaseRekorEntry(): RekorEntry {
  return {
    logIndex: "0",
    logId: "",
    kind: "",
    version: "",
    signedEntryTimestamp: "",
    integratedTime: "0",
  };
}

export const RekorEntry = {
  fromJSON(object: any): RekorEntry {
    return {
      logIndex: isSet(object.logIndex) ? String(object.logIndex) : "0",
      logId: isSet(object.logId) ? String(object.logId) : "",
      kind: isSet(object.kind) ? String(object.kind) : "",
      version: isSet(object.version) ? String(object.version) : "",
      signedEntryTimestamp: isSet(object.signedEntryTimestamp)
        ? String(object.signedEntryTimestamp)
        : "",
      integratedTime: isSet(object.integratedTime)
        ? String(object.integratedTime)
        : "0",
    };
  },

  toJSON(message: RekorEntry): unknown {
    const obj: any = {};
    message.logIndex !== undefined && (obj.logIndex = message.logIndex);
    message.logId !== undefined && (obj.logId = message.logId);
    message.kind !== undefined && (obj.kind = message.kind);
    message.version !== undefined && (obj.version = message.version);
    message.signedEntryTimestamp !== undefined &&
      (obj.signedEntryTimestamp = message.signedEntryTimestamp);
    message.integratedTime !== undefined &&
      (obj.integratedTime = message.integratedTime);
    return obj;
  },
};

function createBasePublicKey(): PublicKey {
  return { keyId: "" };
}

export const PublicKey = {
  fromJSON(object: any): PublicKey {
    return {
      keyId: isSet(object.keyId) ? String(object.keyId) : "",
    };
  },

  toJSON(message: PublicKey): unknown {
    const obj: any = {};
    message.keyId !== undefined && (obj.keyId = message.keyId);
    return obj;
  },
};

function createBaseX509Cert(): X509Cert {
  return { certificate: "", chain: "" };
}

export const X509Cert = {
  fromJSON(object: any): X509Cert {
    return {
      certificate: isSet(object.certificate) ? String(object.certificate) : "",
      chain: isSet(object.chain) ? String(object.chain) : "",
    };
  },

  toJSON(message: X509Cert): unknown {
    const obj: any = {};
    message.certificate !== undefined &&
      (obj.certificate = message.certificate);
    message.chain !== undefined && (obj.chain = message.chain);
    return obj;
  },
};

function createBaseBundle(): Bundle {
  return {
    mediaType: "",
    rekorEntry: undefined,
    verificationMaterial: undefined,
    attestation: undefined,
  };
}

export const Bundle = {
  fromJSON(object: any): Bundle {
    return {
      mediaType: isSet(object.mediaType) ? String(object.mediaType) : "",
      rekorEntry: isSet(object.rekorEntry)
        ? RekorEntry.fromJSON(object.rekorEntry)
        : undefined,
      verificationMaterial: isSet(object.publicKey)
        ? {
            $case: "publicKey",
            publicKey: PublicKey.fromJSON(object.publicKey),
          }
        : isSet(object.x509Cert)
        ? { $case: "x509Cert", x509Cert: X509Cert.fromJSON(object.x509Cert) }
        : undefined,
      attestation: isSet(object.attestationBlob)
        ? {
            $case: "attestationBlob",
            attestationBlob: AttestationBlob.fromJSON(object.attestationBlob),
          }
        : isSet(object.attestationDsse)
        ? {
            $case: "attestationDsse",
            attestationDsse: Envelope.fromJSON(object.attestationDsse),
          }
        : undefined,
    };
  },

  toJSON(message: Bundle): unknown {
    const obj: any = {};
    message.mediaType !== undefined && (obj.mediaType = message.mediaType);
    message.rekorEntry !== undefined &&
      (obj.rekorEntry = message.rekorEntry
        ? RekorEntry.toJSON(message.rekorEntry)
        : undefined);
    message.verificationMaterial?.$case === "publicKey" &&
      (obj.publicKey = message.verificationMaterial?.publicKey
        ? PublicKey.toJSON(message.verificationMaterial?.publicKey)
        : undefined);
    message.verificationMaterial?.$case === "x509Cert" &&
      (obj.x509Cert = message.verificationMaterial?.x509Cert
        ? X509Cert.toJSON(message.verificationMaterial?.x509Cert)
        : undefined);
    message.attestation?.$case === "attestationBlob" &&
      (obj.attestationBlob = message.attestation?.attestationBlob
        ? AttestationBlob.toJSON(message.attestation?.attestationBlob)
        : undefined);
    message.attestation?.$case === "attestationDsse" &&
      (obj.attestationDsse = message.attestation?.attestationDsse
        ? Envelope.toJSON(message.attestation?.attestationDsse)
        : undefined);
    return obj;
  },
};

declare var self: any | undefined;
declare var window: any | undefined;
declare var global: any | undefined;
var globalThis: any = (() => {
  if (typeof globalThis !== "undefined") return globalThis;
  if (typeof self !== "undefined") return self;
  if (typeof window !== "undefined") return window;
  if (typeof global !== "undefined") return global;
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
