import fs from 'fs';
import fetch from 'make-fetch-happen';
import { Sigstore } from '../index';

const sigstore = new Sigstore({});

async function cli(args: string[]) {
  switch (args[0]) {
    case 'sign':
      await sign(args[1], args[2]);
      break;
    case 'sign-dsse':
      await signDSSE(args[1], args[2], args[3]);
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

async function sign(artifactPath: string, token?: string) {
  token = token || process.env.OIDC_TOKEN || (await getGHToken());

  if (!token) {
    throw 'Missing OIDC token';
  }

  const buffer = fs.readFileSync(artifactPath);
  const signature = await sigstore.signRaw(buffer, token);
  console.log(signature.base64Signature);
}

async function signDSSE(
  artifactPath: string,
  payloadType: string,
  token?: string
) {
  token = token || process.env.OIDC_TOKEN || (await getGHToken());

  if (!token) {
    throw 'Missing OIDC token';
  }

  const buffer = fs.readFileSync(artifactPath);
  const envelope = await sigstore.signDSSE(buffer, payloadType, token);
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

async function getGHToken() {
  let token;
  if (
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN &&
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  ) {
    const response = await fetch(
      `${process.env.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore`,
      {
        headers: {
          Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
          Accept: 'application/json',
        },
      }
    );
    const body = await response.json();
    token = body.value;
  }
  return token;
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
