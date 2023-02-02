/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import fs from 'fs';
import { TargetFile, Updater } from 'tuf-js';
import { TrustedRootError } from '../error';
import * as sigstore from '../types/sigstore';
import { crypto, pem } from '../util';

const TRUSTED_ROOT_MEDIA_TYPE =
  'application/vnd.dev.sigstore.trustedroot+json;version=0.1';

// Type describing the Sigstore-specific metadata for a TUF target
interface SigstoreTargetMetadata {
  status: string;
  usage: string;
  uri: string;
}

// Type guard for SigstoreTargetMetadata
function isTargetMetadata(m: unknown): m is SigstoreTargetMetadata {
  return (
    m !== undefined &&
    m !== null &&
    typeof m === 'object' &&
    'status' in m &&
    'usage' in m &&
    'uri' in m
  );
}

export class TrustedRootFetcher {
  private tuf: Updater;
  constructor(tuf: Updater) {
    this.tuf = tuf;
  }

  // Assembles a TrustedRoot from the targets in the TUF repo
  async getTrustedRoot(): Promise<sigstore.TrustedRoot> {
    // Get all available targets
    const targets = await this.allTargets();

    const cas = await this.getCAKeys(targets, 'Fulcio');
    const ctlogs = await this.getTLogKeys(targets, 'CTFE');
    const tlogs = await this.getTLogKeys(targets, 'Rekor');

    return {
      mediaType: TRUSTED_ROOT_MEDIA_TYPE,
      certificateAuthorities: cas,
      ctlogs: ctlogs,
      tlogs: tlogs,
      timestampAuthorities: [],
    };
  }

  // Retrieves the list of TUF targets.
  // NOTE: This is a HACK to get around the fact that the TUF library doesn't
  // expose the list of targets. This is a temporary solution until TUF comes up
  // with a story for target discovery.
  // https://docs.google.com/document/d/1rWHAM2qCUtnjWD4lOrGWE2EIDLoA7eSy4-jB66Wgh0o
  private async allTargets(): Promise<TargetFile[]> {
    try {
      await this.tuf.refresh();
    } catch (e) {
      throw new TrustedRootError('error refreshing trust metadata');
    }

    return Object.values(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (this.tuf as any).trustedSet.targets?.signed.targets || {}
    );
  }

  // Filters the supplied list of targets to those with the specified usage
  // and returns a new TransparencyLogInstance for each with the associated
  // public key populated.
  private async getTLogKeys(
    targets: TargetFile[],
    usage: string
  ): Promise<sigstore.TransparencyLogInstance[]> {
    const filteredTargets = filterByUsage(targets, usage);

    return Promise.all(
      filteredTargets.map(async (target) => {
        const keyBytes = await this.readTargetBytes(target);
        const uri = isTargetMetadata(target.custom.sigstore)
          ? target.custom.sigstore.uri
          : '';

        // The log ID is not present in the Sigstore target metadata, but
        // can be derived by hashing the contents of the public key.
        return {
          baseUrl: uri,
          hashAlgorithm: sigstore.HashAlgorithm.SHA2_256,
          logId: { keyId: crypto.hash(keyBytes) },

          publicKey: {
            keyDetails: sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
            rawBytes: keyBytes,
          },
        };
      })
    );
  }

  // Filters the supplied list of targets to those with the specified usage
  // and returns a new CertificateAuthority populated with all of the associated
  // certificates.
  // NOTE: The Sigstore target metadata does NOT provide any mechanism to link
  // related certificates (e.g. a root and intermediate). As a result, we
  // assume that all certificates located here are part of the same chain.
  // This works out OK since our certificate chain verification code tries all
  // possible permutations of the certificates until it finds one that results
  // in a valid, trusted chain.
  private async getCAKeys(
    targets: TargetFile[],
    usage: string
  ): Promise<sigstore.CertificateAuthority[]> {
    const filteredTargets = filterByUsage(targets, usage);

    const certs = await Promise.all(
      filteredTargets.map(async (target) => await this.readTargetBytes(target))
    );

    return [
      {
        uri: '',
        subject: undefined,
        validFor: { start: new Date(0) },
        certChain: {
          certificates: certs.map((cert) => ({ rawBytes: cert })),
        },
      },
    ];
  }

  // Reads the contents of the specified target file as a DER-encoded buffer.
  private async readTargetBytes(target: TargetFile): Promise<Buffer> {
    try {
      let path = await this.tuf.findCachedTarget(target);

      // An empty path here means the target has not been cached locally, or is
      // out of date. In either case, we need to download it.
      if (!path) {
        path = await this.tuf.downloadTarget(target);
      }

      const file = fs.readFileSync(path);
      return pem.toDER(file.toString('utf-8'));
    } catch (err) {
      throw new TrustedRootError(
        `error reading key/certificate for ${target.path}`
      );
    }
  }
}

function filterByUsage(targets: TargetFile[], usage: string): TargetFile[] {
  return targets.filter((target) => {
    const meta = target.custom.sigstore;
    return isTargetMetadata(meta) && meta.usage === usage;
  });
}
