/* eslint-disable */
import { Envelope } from "./envelope";
import { MessageSignature, PublicKeyIdentifier, RFC3161SignedTimestamp, X509CertificateChain } from "./sigstore_common";
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
   * transparency log, or in conjunction for a stronger trust model.
   * Clients MUST verify the hashed message in the message imprint
   * against the signature in the bundle.
   */
  rfc3161Timestamps: RFC3161SignedTimestamp[];
}

/**
 * VerificationMaterial captures details on the materials used to verify
 * signatures.
 */
export interface VerificationMaterial {
  content?:
    | { $case: "publicKey"; publicKey: PublicKeyIdentifier }
    | { $case: "x509CertificateChain"; x509CertificateChain: X509CertificateChain };
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
  /**
   * When a signer is identified by a X.509 certificate, a verifier MUST
   * verify that the signature was computed at the time the certificate
   * was valid as described in the Sigstore client spec: "Verification
   * using a Bundle".
   * <https://docs.google.com/document/d/1kbhK2qyPPk8SLavHzYSDM8-Ueul9_oxIMVFuWMWKz0E/edit#heading=h.x8bduppe89ln>
   */
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

function createBaseVerificationMaterial(): VerificationMaterial {
  return { content: undefined, tlogEntries: [], timestampVerificationData: undefined };
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
      tlogEntries: Array.isArray(object?.tlogEntries)
        ? object.tlogEntries.map((e: any) => TransparencyLogEntry.fromJSON(e))
        : [],
      timestampVerificationData: isSet(object.timestampVerificationData)
        ? TimestampVerificationData.fromJSON(object.timestampVerificationData)
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
  return { mediaType: "", verificationMaterial: undefined, content: undefined };
}

export const Bundle = {
  fromJSON(object: any): Bundle {
    return {
      mediaType: isSet(object.mediaType) ? String(object.mediaType) : "",
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
