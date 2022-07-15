import * as sigstore from './sigstore';

export interface Signature {
  keyid: string;
  sig: string;
}

export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: Signature[];
}

export async function sign(
  payload: Buffer,
  payloadType: string,
  options: sigstore.SignOptions = {}
): Promise<Envelope> {
  const paeBuffer = pae(payloadType, payload);
  const signedPayload = await sigstore.sign(paeBuffer, options);

  const envelope: Envelope = {
    payloadType: payloadType,
    payload: payload.toString('base64'),
    signatures: [
      {
        keyid: '',
        sig: signedPayload.base64Signature,
      },
    ],
  };

  return envelope;
}

export async function verify(
  envelope: Envelope,
  options: sigstore.VerifierOptions = {}
): Promise<boolean> {
  const payloadType = envelope.payloadType;
  const payload = Buffer.from(envelope.payload, 'base64');
  const signature = envelope.signatures[0].sig;

  const paeBuffer = pae(payloadType, payload);
  const verified = await sigstore.verify(paeBuffer, signature, options);

  return verified;
}

// DSSE Pre-Authentication Encoding
function pae(payloadType: string, payload: Buffer): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    'ascii'
  );
  return Buffer.concat([prefix, payload]);
}
