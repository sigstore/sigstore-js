/* eslint-disable */
import { Bundle } from "./sigstore_bundle";
import { ObjectIdentifierValuePair, PublicKey, SubjectAlternativeName } from "./sigstore_common";
import { TrustedRoot } from "./sigstore_trustroot";

/** The identity of a X.509 Certificate signer. */
export interface CertificateIdentity {
  /** The X.509v3 issuer extension (OID 1.3.6.1.4.1.57264.1.1) */
  issuer: string;
  san:
    | SubjectAlternativeName
    | undefined;
  /**
   * An unordered list of OIDs that must be verified.
   * All OID/values provided in this list MUST exactly match against
   * the values in the certificate for verification to be successful.
   */
  oids: ObjectIdentifierValuePair[];
}

export interface CertificateIdentities {
  identities: CertificateIdentity[];
}

export interface PublicKeyIdentities {
  publicKeys: PublicKey[];
}

/**
 * A light-weight set of options/policies for identifying trusted signers,
 * used during verification of a single artifact.
 */
export interface ArtifactVerificationOptions {
  signers?:
    | { $case: "certificateIdentities"; certificateIdentities: CertificateIdentities }
    | { $case: "publicKeys"; publicKeys: PublicKeyIdentities };
  /**
   * Optional options for artifact transparency log verification.
   * If none is provided, the default verification options are:
   * Threshold: 1
   * Online verification: false
   * Disable: false
   */
  tlogOptions?:
    | ArtifactVerificationOptions_TlogOptions
    | undefined;
  /**
   * Optional options for certificate transparency log verification.
   * If none is provided, the default verification options are:
   * Threshold: 1
   * Detached SCT: false
   * Disable: false
   */
  ctlogOptions?:
    | ArtifactVerificationOptions_CtlogOptions
    | undefined;
  /**
   * Optional options for certificate signed timestamp verification.
   * If none is provided, the default verification options are:
   * Threshold: 1
   * Disable: false
   */
  tsaOptions?: ArtifactVerificationOptions_TimestampAuthorityOptions | undefined;
}

export interface ArtifactVerificationOptions_TlogOptions {
  /** Number of transparency logs the entry must appear on. */
  threshold: number;
  /** Perform an online inclusion proof. */
  performOnlineVerification: boolean;
  /** Disable verification for transparency logs. */
  disable: boolean;
}

export interface ArtifactVerificationOptions_CtlogOptions {
  /**
   * The number of ct transparency logs the certificate must
   * appear on.
   */
  threshold: number;
  /**
   * Expect detached SCTs.
   * This is not supported right now as we can't capture an
   * detached SCT in the bundle.
   */
  detachedSct: boolean;
  /** Disable ct transparency log verification */
  disable: boolean;
}

export interface ArtifactVerificationOptions_TimestampAuthorityOptions {
  /** The number of signed timestamps that are expected. */
  threshold: number;
  /** Disable signed timestamp verification. */
  disable: boolean;
}

export interface Artifact {
  data?: { $case: "artifactUri"; artifactUri: string } | { $case: "artifact"; artifact: Buffer };
}

/**
 * Input captures all that is needed to call the bundle verification method,
 * to verify a single artifact referenced by the bundle.
 */
export interface Input {
  /**
   * The verification materials provided during a bundle verification.
   * The running process is usually preloaded with a "global"
   * dev.sisgtore.trustroot.TrustedRoot.v1 instance. Prior to
   * verifying an artifact (i.e a bundle), and/or based on current
   * policy, some selection is expected to happen, to filter out the
   * exact certificate authority to use, which transparency logs are
   * relevant etc. The result should b ecaptured in the
   * `artifact_trust_root`.
   */
  artifactTrustRoot: TrustedRoot | undefined;
  artifactVerificationOptions: ArtifactVerificationOptions | undefined;
  bundle:
    | Bundle
    | undefined;
  /**
   * If the bundle contains a message signature, the artifact must be
   * provided.
   */
  artifact?: Artifact | undefined;
}

function createBaseCertificateIdentity(): CertificateIdentity {
  return { issuer: "", san: undefined, oids: [] };
}

export const CertificateIdentity = {
  fromJSON(object: any): CertificateIdentity {
    return {
      issuer: isSet(object.issuer) ? String(object.issuer) : "",
      san: isSet(object.san) ? SubjectAlternativeName.fromJSON(object.san) : undefined,
      oids: Array.isArray(object?.oids) ? object.oids.map((e: any) => ObjectIdentifierValuePair.fromJSON(e)) : [],
    };
  },

  toJSON(message: CertificateIdentity): unknown {
    const obj: any = {};
    message.issuer !== undefined && (obj.issuer = message.issuer);
    message.san !== undefined && (obj.san = message.san ? SubjectAlternativeName.toJSON(message.san) : undefined);
    if (message.oids) {
      obj.oids = message.oids.map((e) => e ? ObjectIdentifierValuePair.toJSON(e) : undefined);
    } else {
      obj.oids = [];
    }
    return obj;
  },
};

function createBaseCertificateIdentities(): CertificateIdentities {
  return { identities: [] };
}

export const CertificateIdentities = {
  fromJSON(object: any): CertificateIdentities {
    return {
      identities: Array.isArray(object?.identities)
        ? object.identities.map((e: any) => CertificateIdentity.fromJSON(e))
        : [],
    };
  },

  toJSON(message: CertificateIdentities): unknown {
    const obj: any = {};
    if (message.identities) {
      obj.identities = message.identities.map((e) => e ? CertificateIdentity.toJSON(e) : undefined);
    } else {
      obj.identities = [];
    }
    return obj;
  },
};

function createBasePublicKeyIdentities(): PublicKeyIdentities {
  return { publicKeys: [] };
}

export const PublicKeyIdentities = {
  fromJSON(object: any): PublicKeyIdentities {
    return {
      publicKeys: Array.isArray(object?.publicKeys) ? object.publicKeys.map((e: any) => PublicKey.fromJSON(e)) : [],
    };
  },

  toJSON(message: PublicKeyIdentities): unknown {
    const obj: any = {};
    if (message.publicKeys) {
      obj.publicKeys = message.publicKeys.map((e) => e ? PublicKey.toJSON(e) : undefined);
    } else {
      obj.publicKeys = [];
    }
    return obj;
  },
};

function createBaseArtifactVerificationOptions(): ArtifactVerificationOptions {
  return { signers: undefined, tlogOptions: undefined, ctlogOptions: undefined, tsaOptions: undefined };
}

export const ArtifactVerificationOptions = {
  fromJSON(object: any): ArtifactVerificationOptions {
    return {
      signers: isSet(object.certificateIdentities)
        ? {
          $case: "certificateIdentities",
          certificateIdentities: CertificateIdentities.fromJSON(object.certificateIdentities),
        }
        : isSet(object.publicKeys)
        ? { $case: "publicKeys", publicKeys: PublicKeyIdentities.fromJSON(object.publicKeys) }
        : undefined,
      tlogOptions: isSet(object.tlogOptions)
        ? ArtifactVerificationOptions_TlogOptions.fromJSON(object.tlogOptions)
        : undefined,
      ctlogOptions: isSet(object.ctlogOptions)
        ? ArtifactVerificationOptions_CtlogOptions.fromJSON(object.ctlogOptions)
        : undefined,
      tsaOptions: isSet(object.tsaOptions)
        ? ArtifactVerificationOptions_TimestampAuthorityOptions.fromJSON(object.tsaOptions)
        : undefined,
    };
  },

  toJSON(message: ArtifactVerificationOptions): unknown {
    const obj: any = {};
    message.signers?.$case === "certificateIdentities" &&
      (obj.certificateIdentities = message.signers?.certificateIdentities
        ? CertificateIdentities.toJSON(message.signers?.certificateIdentities)
        : undefined);
    message.signers?.$case === "publicKeys" && (obj.publicKeys = message.signers?.publicKeys
      ? PublicKeyIdentities.toJSON(message.signers?.publicKeys)
      : undefined);
    message.tlogOptions !== undefined && (obj.tlogOptions = message.tlogOptions
      ? ArtifactVerificationOptions_TlogOptions.toJSON(message.tlogOptions)
      : undefined);
    message.ctlogOptions !== undefined && (obj.ctlogOptions = message.ctlogOptions
      ? ArtifactVerificationOptions_CtlogOptions.toJSON(message.ctlogOptions)
      : undefined);
    message.tsaOptions !== undefined && (obj.tsaOptions = message.tsaOptions
      ? ArtifactVerificationOptions_TimestampAuthorityOptions.toJSON(message.tsaOptions)
      : undefined);
    return obj;
  },
};

function createBaseArtifactVerificationOptions_TlogOptions(): ArtifactVerificationOptions_TlogOptions {
  return { threshold: 0, performOnlineVerification: false, disable: false };
}

export const ArtifactVerificationOptions_TlogOptions = {
  fromJSON(object: any): ArtifactVerificationOptions_TlogOptions {
    return {
      threshold: isSet(object.threshold) ? Number(object.threshold) : 0,
      performOnlineVerification: isSet(object.performOnlineVerification)
        ? Boolean(object.performOnlineVerification)
        : false,
      disable: isSet(object.disable) ? Boolean(object.disable) : false,
    };
  },

  toJSON(message: ArtifactVerificationOptions_TlogOptions): unknown {
    const obj: any = {};
    message.threshold !== undefined && (obj.threshold = Math.round(message.threshold));
    message.performOnlineVerification !== undefined &&
      (obj.performOnlineVerification = message.performOnlineVerification);
    message.disable !== undefined && (obj.disable = message.disable);
    return obj;
  },
};

function createBaseArtifactVerificationOptions_CtlogOptions(): ArtifactVerificationOptions_CtlogOptions {
  return { threshold: 0, detachedSct: false, disable: false };
}

export const ArtifactVerificationOptions_CtlogOptions = {
  fromJSON(object: any): ArtifactVerificationOptions_CtlogOptions {
    return {
      threshold: isSet(object.threshold) ? Number(object.threshold) : 0,
      detachedSct: isSet(object.detachedSct) ? Boolean(object.detachedSct) : false,
      disable: isSet(object.disable) ? Boolean(object.disable) : false,
    };
  },

  toJSON(message: ArtifactVerificationOptions_CtlogOptions): unknown {
    const obj: any = {};
    message.threshold !== undefined && (obj.threshold = Math.round(message.threshold));
    message.detachedSct !== undefined && (obj.detachedSct = message.detachedSct);
    message.disable !== undefined && (obj.disable = message.disable);
    return obj;
  },
};

function createBaseArtifactVerificationOptions_TimestampAuthorityOptions(): ArtifactVerificationOptions_TimestampAuthorityOptions {
  return { threshold: 0, disable: false };
}

export const ArtifactVerificationOptions_TimestampAuthorityOptions = {
  fromJSON(object: any): ArtifactVerificationOptions_TimestampAuthorityOptions {
    return {
      threshold: isSet(object.threshold) ? Number(object.threshold) : 0,
      disable: isSet(object.disable) ? Boolean(object.disable) : false,
    };
  },

  toJSON(message: ArtifactVerificationOptions_TimestampAuthorityOptions): unknown {
    const obj: any = {};
    message.threshold !== undefined && (obj.threshold = Math.round(message.threshold));
    message.disable !== undefined && (obj.disable = message.disable);
    return obj;
  },
};

function createBaseArtifact(): Artifact {
  return { data: undefined };
}

export const Artifact = {
  fromJSON(object: any): Artifact {
    return {
      data: isSet(object.artifactUri)
        ? { $case: "artifactUri", artifactUri: String(object.artifactUri) }
        : isSet(object.artifact)
        ? { $case: "artifact", artifact: Buffer.from(bytesFromBase64(object.artifact)) }
        : undefined,
    };
  },

  toJSON(message: Artifact): unknown {
    const obj: any = {};
    message.data?.$case === "artifactUri" && (obj.artifactUri = message.data?.artifactUri);
    message.data?.$case === "artifact" &&
      (obj.artifact = message.data?.artifact !== undefined ? base64FromBytes(message.data?.artifact) : undefined);
    return obj;
  },
};

function createBaseInput(): Input {
  return {
    artifactTrustRoot: undefined,
    artifactVerificationOptions: undefined,
    bundle: undefined,
    artifact: undefined,
  };
}

export const Input = {
  fromJSON(object: any): Input {
    return {
      artifactTrustRoot: isSet(object.artifactTrustRoot) ? TrustedRoot.fromJSON(object.artifactTrustRoot) : undefined,
      artifactVerificationOptions: isSet(object.artifactVerificationOptions)
        ? ArtifactVerificationOptions.fromJSON(object.artifactVerificationOptions)
        : undefined,
      bundle: isSet(object.bundle) ? Bundle.fromJSON(object.bundle) : undefined,
      artifact: isSet(object.artifact) ? Artifact.fromJSON(object.artifact) : undefined,
    };
  },

  toJSON(message: Input): unknown {
    const obj: any = {};
    message.artifactTrustRoot !== undefined &&
      (obj.artifactTrustRoot = message.artifactTrustRoot ? TrustedRoot.toJSON(message.artifactTrustRoot) : undefined);
    message.artifactVerificationOptions !== undefined &&
      (obj.artifactVerificationOptions = message.artifactVerificationOptions
        ? ArtifactVerificationOptions.toJSON(message.artifactVerificationOptions)
        : undefined);
    message.bundle !== undefined && (obj.bundle = message.bundle ? Bundle.toJSON(message.bundle) : undefined);
    message.artifact !== undefined && (obj.artifact = message.artifact ? Artifact.toJSON(message.artifact) : undefined);
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
