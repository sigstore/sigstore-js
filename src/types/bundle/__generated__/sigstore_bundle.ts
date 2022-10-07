/* eslint-disable */
import { Envelope } from "./envelope";
import { MessageSignature, RFC3161SignedTimestamp, VerificationMaterial } from "./sigstore_common";
import { TransparencyLogEntry } from "./sigstore_rekor";

/**
 * This message holds different constructs that captures the timestamp
 * of the time the signature was generated.
 * As this message can be either empty (no timestamps), or a combination of
 * an arbitrarily number of transparency log entries and signed timestamps,
 * it is the client's responsibility to implement any required verification
 * policies.
 */
export interface TimestampVerificationData {
  /**
   * This is the regular inclusion promise and proof, where
   * the timestamp is coming from the transparency log.
   */
  tlogEntries: TransparencyLogEntry[];
  /**
   * A list of RFC3161 signed timestamps provided by the user.
   * This can be used when the entry has not been stored on a
   * transparency log.
   * Clients MUST verify the hashed message in the message imprint
   * against the artifact. Note that the message hash algorithm may
   * differ from the one in message signature, or the subject of the
   * DSSE envelope.
   */
  rfc3161Timestamps: RFC3161SignedTimestamp[];
}

export interface Bundle {
  /**
   * MUST be application/vnd.dev.sigstore.bundle+json;version=0.1
   * when encoded as JSON.
   */
  mediaType: string;
  timestampVerificationData: TimestampVerificationData | undefined;
  verificationMaterial: VerificationMaterial | undefined;
  content?: { $case: "messageSignature"; messageSignature: MessageSignature } | {
    $case: "dsseEnvelope";
    dsseEnvelope: Envelope;
  };
}

function createBaseTimestampVerificationData(): TimestampVerificationData {
  return { tlogEntries: [], rfc3161Timestamps: [] };
}

export const TimestampVerificationData = {
  fromJSON(object: any): TimestampVerificationData {
    return {
      tlogEntries: Array.isArray(object?.tlogEntries)
        ? object.tlogEntries.map((e: any) => TransparencyLogEntry.fromJSON(e))
        : [],
      rfc3161Timestamps: Array.isArray(object?.rfc3161Timestamps)
        ? object.rfc3161Timestamps.map((e: any) => RFC3161SignedTimestamp.fromJSON(e))
        : [],
    };
  },

  toJSON(message: TimestampVerificationData): unknown {
    const obj: any = {};
    if (message.tlogEntries) {
      obj.tlogEntries = message.tlogEntries.map((e) => e ? TransparencyLogEntry.toJSON(e) : undefined);
    } else {
      obj.tlogEntries = [];
    }
    if (message.rfc3161Timestamps) {
      obj.rfc3161Timestamps = message.rfc3161Timestamps.map((e) => e ? RFC3161SignedTimestamp.toJSON(e) : undefined);
    } else {
      obj.rfc3161Timestamps = [];
    }
    return obj;
  },
};

function createBaseBundle(): Bundle {
  return { mediaType: "", timestampVerificationData: undefined, verificationMaterial: undefined, content: undefined };
}

export const Bundle = {
  fromJSON(object: any): Bundle {
    return {
      mediaType: isSet(object.mediaType) ? String(object.mediaType) : "",
      timestampVerificationData: isSet(object.timestampVerificationData)
        ? TimestampVerificationData.fromJSON(object.timestampVerificationData)
        : undefined,
      verificationMaterial: isSet(object.verificationMaterial)
        ? VerificationMaterial.fromJSON(object.verificationMaterial)
        : undefined,
      content: isSet(object.messageSignature)
        ? { $case: "messageSignature", messageSignature: MessageSignature.fromJSON(object.messageSignature) }
        : isSet(object.dsseEnvelope)
        ? { $case: "dsseEnvelope", dsseEnvelope: Envelope.fromJSON(object.dsseEnvelope) }
        : undefined,
    };
  },

  toJSON(message: Bundle): unknown {
    const obj: any = {};
    message.mediaType !== undefined && (obj.mediaType = message.mediaType);
    message.timestampVerificationData !== undefined &&
      (obj.timestampVerificationData = message.timestampVerificationData
        ? TimestampVerificationData.toJSON(message.timestampVerificationData)
        : undefined);
    message.verificationMaterial !== undefined && (obj.verificationMaterial = message.verificationMaterial
      ? VerificationMaterial.toJSON(message.verificationMaterial)
      : undefined);
    message.content?.$case === "messageSignature" && (obj.messageSignature = message.content?.messageSignature
      ? MessageSignature.toJSON(message.content?.messageSignature)
      : undefined);
    message.content?.$case === "dsseEnvelope" &&
      (obj.dsseEnvelope = message.content?.dsseEnvelope ? Envelope.toJSON(message.content?.dsseEnvelope) : undefined);
    return obj;
  },
};

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
