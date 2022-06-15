import fs from 'fs';
import { Sigstore } from '../index';

const sigstore = new Sigstore({
  oidcClientID: 'sigstore',
  oidcIssuer: 'https://oauth2.sigstore.dev/auth',
});

async function cli(args: string[]) {
  switch (args[0]) {
    case 'sign':
      await sign(args[1]);
      break;
    case 'sign-dsse':
      await signDSSE(args[1], args[2]);
      break;
    case 'verify':
      await verify(args[1], args[2]);
      break;
    case 'verify-dsse':
      await verifyDSSE(args[1]);
      break;
    default:
      throw 'Unknown command';
  }
}

async function sign(artifactPath: string) {
  const buffer = fs.readFileSync(artifactPath);
  const signature = await sigstore.signRaw(buffer);
  console.log(signature.base64Signature);
}

async function signDSSE(artifactPath: string, payloadType: string) {
  const buffer = fs.readFileSync(artifactPath);
  const envelope = await sigstore.signDSSE(buffer, payloadType);
  console.log(JSON.stringify(envelope));
}

async function verify(artifactPath: string, signaturePath: string) {
  const payload = fs.readFileSync(artifactPath);
  const sig = fs.readFileSync(signaturePath);
  const result = await sigstore.verifyOnline(payload, sig.toString('utf8'));

  if (result) {
    console.error('Verified OK');
  } else {
    throw 'Signature verification failed';
  }
}

async function verifyDSSE(artifactPath: string) {
  const envelope = fs.readFileSync(artifactPath);
  const result = await sigstore.verifyDSSE(
    JSON.parse(envelope.toString('utf-8'))
  );

  if (result) {
    console.error('Verified OK');
  } else {
    throw 'Signature verification failed';
  }
}

export async function processArgv(): Promise<void> {
  try {
    await cli(process.argv.slice(2));
    process.exit(0);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}
