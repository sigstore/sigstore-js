import { Args, Command, Flags } from '@oclif/core';
import { Bundle, bundleFromJSON, MessageSignature } from '@sigstore/bundle';
import { TrustedRoot } from '@sigstore/protobuf-specs';
import * as tuf from '@sigstore/tuf';
import {
  SignedEntity,
  toSignedEntity,
  toTrustMaterial,
  TrustMaterial,
  Verifier,
} from '@sigstore/verify';
import { ec as EC } from 'elliptic';
import { existsSync } from 'fs';
import fs from 'fs/promises';
import crypto from 'node:crypto';
import os from 'os';
import path from 'path';
import { TUF_STAGING_ROOT, TUF_STAGING_URL } from '../staging';

const DIGEST_PREFIX = 'sha256:';

export default class VerifyBundle extends Command {
  static override flags = {
    bundle: Flags.string({
      description: 'path to bundle',
      required: true,
    }),
    'certificate-identity': Flags.string({
      description:
        'The expected identity in the signing ceritifcate SAN extension',
      required: true,
    }),
    'certificate-oidc-issuer': Flags.string({
      description: 'the expected OIDC issuer for the signing certificate',
      required: true,
    }),
    'trusted-root': Flags.string({
      description: 'path to trusted root',
      required: false,
    }),
    staging: Flags.boolean({
      description: 'whether to use the staging environment',
      default: false,
    }),
  };

  static override args = {
    fileOrDigest: Args.string({
      description: 'path to the artifact to verify, or its digest',
      required: true,
    }),
  };

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(VerifyBundle);

    const trustedRootPath = flags['trusted-root'];
    const bundle = await fs
      .readFile(flags.bundle)
      .then((data) => JSON.parse(data.toString()))
      .then((json) => bundleFromJSON(json));

    const trustMaterial = trustedRootPath
      ? await trustMaterialFromPath(trustedRootPath)
      : await trustMaterialFromTUF(flags['staging']);
    const verifier = new Verifier(trustMaterial);

    const policy = {
      subjectAlternativeName: flags['certificate-identity'],
      extensions: { issuer: flags['certificate-oidc-issuer'] },
    };

    const signedEntity = isDigest(args.fileOrDigest)
      ? await signedEntityFromDigest(bundle, args.fileOrDigest)
      : await signedEntityFromFile(bundle, args.fileOrDigest);

    verifier.verify(signedEntity, policy);
  }
}

// Initialize TrustMaterial from TUF
async function trustMaterialFromTUF(staging: boolean): Promise<TrustMaterial> {
  const opts: tuf.TUFOptions = {};

  if (staging) {
    // Write the initial root.json to a temporary directory
    const tmpPath = await fs.mkdtemp(path.join(os.tmpdir(), 'sigstore-'));
    const rootPath = path.join(tmpPath, 'root.json');
    await fs.writeFile(rootPath, Buffer.from(TUF_STAGING_ROOT, 'base64'));

    opts.mirrorURL = TUF_STAGING_URL;
    opts.rootPath = rootPath;
  }

  const trustedRoot = await tuf.getTrustedRoot(opts);
  return toTrustMaterial(trustedRoot);
}

// Initialize TrustMaterial from a file
async function trustMaterialFromPath(path: string): Promise<TrustMaterial> {
  const trustedRoot = await fs
    .readFile(path)
    .then((data) => JSON.parse(data.toString()));
  return toTrustMaterial(TrustedRoot.fromJSON(trustedRoot));
}

// Initialize SignedEntity with the artifact to verify
async function signedEntityFromFile(
  bundle: Bundle,
  fileOrDigest: string
): Promise<SignedEntity> {
  const artifact = await fs.readFile(fileOrDigest);
  return toSignedEntity(bundle, artifact);
}

// Initialize SignedEntity with the digest of the artifact to verify
async function signedEntityFromDigest(
  bundle: Bundle,
  digest: string
): Promise<SignedEntity> {
  const signedEntity = toSignedEntity(bundle);

  if (bundle.content.$case === 'messageSignature') {
    signedEntity.signature = new MessageDigestSignatureContent(
      bundle.content.messageSignature,
      digest.split(':')[1]
    );
  }

  return signedEntity;
}

function isDigest(fileOrDigest: string): boolean {
  return (
    fileOrDigest.startsWith(DIGEST_PREFIX) &&
    fileOrDigest.length === 64 + DIGEST_PREFIX.length &&
    !existsSync(fileOrDigest)
  );
}

// Signature content implementation which can verify an artifact's signature
// given the digest of the artifact. The default implementation requires the
// artifact itself, which is not available when verifying a digest.
// The crypto library in Node.js does not provide a way to verify a signature
// given only the digest of the signed data. To work around this, we're using
// the elliptic library to verify the signature on the digest directly.
class MessageDigestSignatureContent {
  constructor(
    private messageSignature: MessageSignature,
    private digest: string
  ) {
    this.messageSignature = messageSignature;
    this.digest = digest;
  }

  get signature(): Buffer {
    return this.messageSignature.signature;
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.timingSafeEqual(signature, this.signature);
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.timingSafeEqual(
      digest,
      this.messageSignature.messageDigest.digest
    );
  }

  verifySignature(key: crypto.KeyObject): boolean {
    // Export public key to JWK format
    const jwk = key.export({ format: 'jwk' });
    const ec = initEC(key.asymmetricKeyDetails?.namedCurve);

    // Create an elliptic-compatible key from the JWK
    const eckey = ec.keyFromPublic(
      {
        x: Buffer.from(jwk.x!, 'base64').toString('hex'),
        y: Buffer.from(jwk.y!, 'base64').toString('hex'),
      },
      'hex'
    );

    return eckey.verify(this.digest, this.signature);
  }
}

function initEC(curve: string | undefined): EC {
  console.log(curve);
  switch (curve) {
    case 'prime256v1':
      return new EC('p256');
    case 'secp384r1':
      return new EC('p384');
    default:
      throw new Error(`unsupported curve: ${curve}`);
  }
}
