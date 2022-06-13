export interface Signature {
  keyid: string;
  sig: string;
}

export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: Signature[];
}

// DSSE Pre-Authentication Encoding
export function pae(payloadType: string, payload: Buffer): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    'ascii'
  );
  return Buffer.concat([prefix, payload]);
}
