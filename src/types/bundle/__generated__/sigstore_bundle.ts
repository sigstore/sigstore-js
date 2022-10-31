/* eslint-disable */
import { Envelope } from "./envelope";
import { MessageSignature, RFC3161SignedTimestamp, VerificationMaterial } from "./sigstore_common";
import { TransparencyLogEntry } from "./sigstore_rekor";

/**
 * Various timestamped counter signatures over the artifacts signature.
 * Currently only RFC3161 signatures are provided. More formats may be added
 * in the future.
 */
export interface TimestampVerificationData {
  /**
   * A list of RFC3161 signed timestamps provided by the user.
   * This can be used when the entry has not been stored on a
   * transparency log, or in conjuction for a stronger trust model.
   * Clients MUST verify the hashed message in the message imprint
   * against the signature in the bundle.
   */
  rfc3161Timestamps: RFC3161SignedTimestamp[];
}

/**
 * VerificationData contains extra data that can be used to verify things
 * such as transparency and timestamp of the signature creation.
 * As this message can be either empty (no inclusion proof or timestamps), or a combination of
 * an arbitrarily number of transparency log entries and signed timestamps,
 * it is the client's responsibility to implement any required verification
 * policies.
 */
export interface VerificationData {
  /**
   * This is the inclusion promise and/or proof, where
   * the timestamp is coming from the transparency log.
   */
  tlogEntries: TransparencyLogEntry[];
  /** Timestamp verification data, over the artifact's signature. */
  timestampVerificationData: TimestampVerificationData | undefined;
}

export interface Bundle {
  /**
   * MUST be application/vnd.dev.sigstore.bundle+json;version=0.1
   * when encoded as JSON.
   */
  mediaType: string;
  verificationData: VerificationData | undefined;
  verificationMaterial: VerificationMaterial | undefined;
  content?: { $case: "messageSignature"; messageSignature: MessageSignature } | {
    $case: "dsseEnvelope";
    dsseEnvelope: Envelope;
  };
}

function createBaseTimestampVerificationData(): TimestampVerificationData {
  return { rfc3161Timestamps: [] };
}

export const TimestampVerificationData = {
  fromJSON(object: any): TimestampVerificationData {
    return {
      rfc3161Timestamps: Array.isArray(object?.rfc3161Timestamps)
        ? object.rfc3161Timestamps.map((e: any) => RFC3161SignedTimestamp.fromJSON(e))
        : [],
    };
  },

  toJSON(message: TimestampVerificationData): unknown {
    const obj: any = {};
    if (message.rfc3161Timestamps) {
      obj.rfc3161Timestamps = message.rfc3161Timestamps.map((e) => e ? RFC3161SignedTimestamp.toJSON(e) : undefined);
    } else {
      obj.rfc3161Timestamps = [];
    }
    return obj;
  },
};

function createBaseVerificationData(): VerificationData {
  return { tlogEntries: [], timestampVerificationData: undefined };
}

export const VerificationData = {
  fromJSON(object: any): VerificationData {
    return {
      tlogEntries: Array.isArray(object?.tlogEntries)
        ? object.tlogEntries.map((e: any) => TransparencyLogEntry.fromJSON(e))
        : [],
      timestampVerificationData: isSet(object.timestampVerificationData)
        ? TimestampVerificationData.fromJSON(object.timestampVerificationData)
        : undefined,
    };
  },

  toJSON(message: VerificationData): unknown {
    const obj: any = {};
    if (message.tlogEntries) {
      obj.tlogEntries = message.tlogEntries.map((e) => e ? TransparencyLogEntry.toJSON(e) : undefined);
    } else {
      obj.tlogEntries = [];
    }
    message.timestampVerificationData !== undefined &&
      (obj.timestampVerificationData = message.timestampVerificationData
        ? TimestampVerificationData.toJSON(message.timestampVerificationData)
        : undefined);
    return obj;
  },
};

function createBaseBundle(): Bundle {
  return { mediaType: "", verificationData: undefined, verificationMaterial: undefined, content: undefined };
}

export const Bundle = {
  fromJSON(object: any): Bundle {
    return {
      mediaType: isSet(object.mediaType) ? String(object.mediaType) : "",
      verificationData: isSet(object.verificationData) ? VerificationData.fromJSON(object.verificationData) : undefined,
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
    message.verificationData !== undefined &&
      (obj.verificationData = message.verificationData ? VerificationData.toJSON(message.verificationData) : undefined);
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
