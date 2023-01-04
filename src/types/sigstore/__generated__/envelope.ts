/* eslint-disable */

/** An authenticated message of arbitrary type. */
export interface Envelope {
  /**
   * Message to be signed. (In JSON, this is encoded as base64.)
   * REQUIRED.
   */
  payload: Buffer;
  /**
   * String unambiguously identifying how to interpret payload.
   * REQUIRED.
   */
  payloadType: string;
  /**
   * Signature over:
   *     PAE(type, body)
   * Where PAE is defined as:
   * PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
   * +               = concatenation
   * SP              = ASCII space [0x20]
   * "DSSEv1"        = ASCII [0x44, 0x53, 0x53, 0x45, 0x76, 0x31]
   * LEN(s)          = ASCII decimal encoding of the byte length of s, with no leading zeros
   * REQUIRED (length >= 1).
   */
  signatures: Signature[];
}

export interface Signature {
  /**
   * Signature itself. (In JSON, this is encoded as base64.)
   * REQUIRED.
   */
  sig: Buffer;
  /**
   * Unauthenticated* hint identifying which public key was used.
   * OPTIONAL.
   */
  keyid: string;
}

function createBaseEnvelope(): Envelope {
  return { payload: Buffer.alloc(0), payloadType: "", signatures: [] };
}

export const Envelope = {
  fromJSON(object: any): Envelope {
    return {
      payload: isSet(object.payload) ? Buffer.from(bytesFromBase64(object.payload)) : Buffer.alloc(0),
      payloadType: isSet(object.payloadType) ? String(object.payloadType) : "",
      signatures: Array.isArray(object?.signatures) ? object.signatures.map((e: any) => Signature.fromJSON(e)) : [],
    };
  },

  toJSON(message: Envelope): unknown {
    const obj: any = {};
    message.payload !== undefined &&
      (obj.payload = base64FromBytes(message.payload !== undefined ? message.payload : Buffer.alloc(0)));
    message.payloadType !== undefined && (obj.payloadType = message.payloadType);
    if (message.signatures) {
      obj.signatures = message.signatures.map((e) => e ? Signature.toJSON(e) : undefined);
    } else {
      obj.signatures = [];
    }
    return obj;
  },
};

function createBaseSignature(): Signature {
  return { sig: Buffer.alloc(0), keyid: "" };
}

export const Signature = {
  fromJSON(object: any): Signature {
    return {
      sig: isSet(object.sig) ? Buffer.from(bytesFromBase64(object.sig)) : Buffer.alloc(0),
      keyid: isSet(object.keyid) ? String(object.keyid) : "",
    };
  },

  toJSON(message: Signature): unknown {
    const obj: any = {};
    message.sig !== undefined && (obj.sig = base64FromBytes(message.sig !== undefined ? message.sig : Buffer.alloc(0)));
    message.keyid !== undefined && (obj.keyid = message.keyid);
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
