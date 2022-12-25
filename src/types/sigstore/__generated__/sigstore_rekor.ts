/* eslint-disable */
import { LogId } from "./sigstore_common";

/** KindVersion contains the entry's kind and api version. */
export interface KindVersion {
  /**
   * Kind is the type of entry being stored in the log.
   * See here for a list: https://github.com/sigstore/rekor/tree/main/pkg/types
   */
  kind: string;
  /** The specific api version of the type. */
  version: string;
}

/**
 * The checkpoint contains a signature of the tree head (root hash),
 * size of the tree, the transparency log's unique identifier (log ID),
 * hostname and the current time.
 * The result is a string, the format is described here
 * https://github.com/transparency-dev/formats/blob/main/log/README.md
 * The details are here https://github.com/sigstore/rekor/blob/a6e58f72b6b18cc06cefe61808efd562b9726330/pkg/util/signed_note.go#L114
 * The signature has the same format as
 * InclusionPromise.signed_entry_timestamp. See below for more details.
 */
export interface Checkpoint {
  envelope: string;
}

/**
 * InclusionProof is the proof returned from the transparency log. Can
 * be used for on line verification against the log.
 */
export interface InclusionProof {
  /** The index of the entry in the log. */
  logIndex: string;
  /**
   * The hash digest stored at the root of the merkle tree at the time
   * the proof was generated.
   */
  rootHash: Buffer;
  /** The size of the merkle tree at the time the proof was generated. */
  treeSize: string;
  /**
   * A list of hashes required to compute the inclusion proof, sorted
   * in order from leaf to root.
   * Not that leaf and root hashes are not included.
   * The root has is available separately in this message, and the
   * leaf hash should be calculated by the client.
   */
  hashes: Buffer[];
  /**
   * Signature of the tree head, as of the time of this proof was
   * generated. See above info on 'Checkpoint' for more details.
   */
  checkpoint: Checkpoint | undefined;
}

/**
 * The inclusion promise is calculated by Rekor. It's calculated as a
 * signature over a canonical JSON serialization of the persisted entry, the
 * log ID, log index and the integration timestamp.
 * See https://github.com/sigstore/rekor/blob/a6e58f72b6b18cc06cefe61808efd562b9726330/pkg/api/entries.go#L54
 * The format of the signature depends on the transparency log's public key.
 * If the signature algorithm requires a hash function and/or a signature
 * scheme (e.g. RSA) those has to be retrieved out-of-band from the log's
 * operators, together with the public key.
 * This is used to verify the integration timestamp's value and that the log
 * has promised to include the entry.
 */
export interface InclusionPromise {
  signedEntryTimestamp: Buffer;
}

/**
 * TransparencyLogEntry captures all the details required from Rekor to
 * reconstruct an entry, given that the payload is provided via other means.
 * This type can easily be created from the existing response from Rekor.
 * Future iterations could rely on Rekor returning the minimal set of
 * attributes (excluding the payload) that are required for verifying the
 * inclusion promise. The inclusion promise (called SignedEntryTimestamp in
 * the response from Rekor) is similar to a Signed Certificate Timestamp
 * as described here https://www.rfc-editor.org/rfc/rfc9162#name-signed-certificate-timestam.
 */
export interface TransparencyLogEntry {
  /** The index of the entry in the log. */
  logIndex: string;
  /** The unique identifier of the log. */
  logId:
    | LogId
    | undefined;
  /**
   * The kind (type) and version of the object associated with this
   * entry. These values are required to construct the entry during
   * verification.
   */
  kindVersion:
    | KindVersion
    | undefined;
  /** The UNIX timestamp from the log when the entry was persisted. */
  integratedTime: string;
  /** The inclusion promise/signed entry timestamp from the log. */
  inclusionPromise:
    | InclusionPromise
    | undefined;
  /**
   * The inclusion proof can be used for online verification that the
   * entry was appended to the log, and that the log has not been
   * altered.
   */
  inclusionProof:
    | InclusionProof
    | undefined;
  /**
   * The canonicalized Rekor entry body, used for SET verification. This
   * is the same as the body returned by Rekor. It's included here for
   * cases where the client cannot deterministically reconstruct the
   * bundle from the other fields. Clients MUST verify that the signature
   * referenced in the canonicalized_body matches the signature provided
   * in the bundle content.
   */
  canonicalizedBody: Buffer;
}

function createBaseKindVersion(): KindVersion {
  return { kind: "", version: "" };
}

export const KindVersion = {
  fromJSON(object: any): KindVersion {
    return {
      kind: isSet(object.kind) ? String(object.kind) : "",
      version: isSet(object.version) ? String(object.version) : "",
    };
  },

  toJSON(message: KindVersion): unknown {
    const obj: any = {};
    message.kind !== undefined && (obj.kind = message.kind);
    message.version !== undefined && (obj.version = message.version);
    return obj;
  },
};

function createBaseCheckpoint(): Checkpoint {
  return { envelope: "" };
}

export const Checkpoint = {
  fromJSON(object: any): Checkpoint {
    return { envelope: isSet(object.envelope) ? String(object.envelope) : "" };
  },

  toJSON(message: Checkpoint): unknown {
    const obj: any = {};
    message.envelope !== undefined && (obj.envelope = message.envelope);
    return obj;
  },
};

function createBaseInclusionProof(): InclusionProof {
  return { logIndex: "0", rootHash: Buffer.alloc(0), treeSize: "0", hashes: [], checkpoint: undefined };
}

export const InclusionProof = {
  fromJSON(object: any): InclusionProof {
    return {
      logIndex: isSet(object.logIndex) ? String(object.logIndex) : "0",
      rootHash: isSet(object.rootHash) ? Buffer.from(bytesFromBase64(object.rootHash)) : Buffer.alloc(0),
      treeSize: isSet(object.treeSize) ? String(object.treeSize) : "0",
      hashes: Array.isArray(object?.hashes) ? object.hashes.map((e: any) => Buffer.from(bytesFromBase64(e))) : [],
      checkpoint: isSet(object.checkpoint) ? Checkpoint.fromJSON(object.checkpoint) : undefined,
    };
  },

  toJSON(message: InclusionProof): unknown {
    const obj: any = {};
    message.logIndex !== undefined && (obj.logIndex = message.logIndex);
    message.rootHash !== undefined &&
      (obj.rootHash = base64FromBytes(message.rootHash !== undefined ? message.rootHash : Buffer.alloc(0)));
    message.treeSize !== undefined && (obj.treeSize = message.treeSize);
    if (message.hashes) {
      obj.hashes = message.hashes.map((e) => base64FromBytes(e !== undefined ? e : Buffer.alloc(0)));
    } else {
      obj.hashes = [];
    }
    message.checkpoint !== undefined &&
      (obj.checkpoint = message.checkpoint ? Checkpoint.toJSON(message.checkpoint) : undefined);
    return obj;
  },
};

function createBaseInclusionPromise(): InclusionPromise {
  return { signedEntryTimestamp: Buffer.alloc(0) };
}

export const InclusionPromise = {
  fromJSON(object: any): InclusionPromise {
    return {
      signedEntryTimestamp: isSet(object.signedEntryTimestamp)
        ? Buffer.from(bytesFromBase64(object.signedEntryTimestamp))
        : Buffer.alloc(0),
    };
  },

  toJSON(message: InclusionPromise): unknown {
    const obj: any = {};
    message.signedEntryTimestamp !== undefined &&
      (obj.signedEntryTimestamp = base64FromBytes(
        message.signedEntryTimestamp !== undefined ? message.signedEntryTimestamp : Buffer.alloc(0),
      ));
    return obj;
  },
};

function createBaseTransparencyLogEntry(): TransparencyLogEntry {
  return {
    logIndex: "0",
    logId: undefined,
    kindVersion: undefined,
    integratedTime: "0",
    inclusionPromise: undefined,
    inclusionProof: undefined,
    canonicalizedBody: Buffer.alloc(0),
  };
}

export const TransparencyLogEntry = {
  fromJSON(object: any): TransparencyLogEntry {
    return {
      logIndex: isSet(object.logIndex) ? String(object.logIndex) : "0",
      logId: isSet(object.logId) ? LogId.fromJSON(object.logId) : undefined,
      kindVersion: isSet(object.kindVersion) ? KindVersion.fromJSON(object.kindVersion) : undefined,
      integratedTime: isSet(object.integratedTime) ? String(object.integratedTime) : "0",
      inclusionPromise: isSet(object.inclusionPromise) ? InclusionPromise.fromJSON(object.inclusionPromise) : undefined,
      inclusionProof: isSet(object.inclusionProof) ? InclusionProof.fromJSON(object.inclusionProof) : undefined,
      canonicalizedBody: isSet(object.canonicalizedBody)
        ? Buffer.from(bytesFromBase64(object.canonicalizedBody))
        : Buffer.alloc(0),
    };
  },

  toJSON(message: TransparencyLogEntry): unknown {
    const obj: any = {};
    message.logIndex !== undefined && (obj.logIndex = message.logIndex);
    message.logId !== undefined && (obj.logId = message.logId ? LogId.toJSON(message.logId) : undefined);
    message.kindVersion !== undefined &&
      (obj.kindVersion = message.kindVersion ? KindVersion.toJSON(message.kindVersion) : undefined);
    message.integratedTime !== undefined && (obj.integratedTime = message.integratedTime);
    message.inclusionPromise !== undefined &&
      (obj.inclusionPromise = message.inclusionPromise ? InclusionPromise.toJSON(message.inclusionPromise) : undefined);
    message.inclusionProof !== undefined &&
      (obj.inclusionProof = message.inclusionProof ? InclusionProof.toJSON(message.inclusionProof) : undefined);
    message.canonicalizedBody !== undefined &&
      (obj.canonicalizedBody = base64FromBytes(
        message.canonicalizedBody !== undefined ? message.canonicalizedBody : Buffer.alloc(0),
      ));
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
