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
import type { Endorsement, KeyMaterial, Signatory } from '../signatory';
import type {
  RFC3161SignedTimestamp,
  TransparencyLogEntry,
  ValidBundle,
} from '../types/sigstore';
import type { Witness } from '../witness';

export interface NotaryOptions {
  signatory: Signatory;
  witnesses: Witness[];
}

// Representation of the artifact to be signed. Includes the raw bytes of the
// artifact and an optional MIME type.
export interface Artifact {
  data: Buffer;
  type?: string;
}

// Interface for notary implementations. A notary is responsible for signing
// and witnessing an artifact.
export interface Notary {
  notarize: (artifact: Artifact) => Promise<ValidBundle>;
}

// BaseNotary is a base class for Notary implementations. It provides a
// the basic wokflow for signing and witnessing an artifact. Subclasses
// must implement the `package` method to assemble a valid bundle with the
// generated signature and verification material.
export abstract class BaseNotary implements Notary {
  protected signatory: Signatory;
  private witnesses: Witness[];

  constructor(options: NotaryOptions) {
    this.signatory = options.signatory;
    this.witnesses = options.witnesses;
  }

  // Executes the signing/witnessing process for the given artifact.
  public async notarize(artifact: Artifact): Promise<ValidBundle> {
    const endorsement = await this.prepare(artifact).then((blob) =>
      this.signatory.sign(blob)
    );
    const bundle = await this.package(artifact, endorsement);

    // Invoke all of the witnesses in parallel
    const witnessResults = await Promise.all(
      this.witnesses.map((witness) =>
        witness.testify(bundle.content, publicKey(endorsement.key))
      )
    );

    // Collect the verification material from all of the witnesses
    const tlogEntries: TransparencyLogEntry[] = [];
    const timestamps: RFC3161SignedTimestamp[] = [];

    witnessResults.forEach((vm) => {
      tlogEntries.push(...vm.tlogEntries);
      timestamps.push(
        ...(vm.timestampVerificationData?.rfc3161Timestamps ?? [])
      );
    });

    // Merge the collected verification material into the bundle
    bundle.verificationMaterial.tlogEntries = tlogEntries;
    bundle.verificationMaterial.timestampVerificationData = {
      rfc3161Timestamps: timestamps,
    };

    return bundle;
  }

  // Override this function to apply any pre-signing transformations to the
  // artifact. The returned buffer will be signed by the signatory.
  // The default implementation simply returns the artifact data.
  protected async prepare(artifact: Artifact): Promise<Buffer> {
    return artifact.data;
  }

  // Override this function to package the artifact and endorsement into a
  // bundle. Any verification material from the configured witnesses will be
  // merged into the bundle.
  protected abstract package(
    artifact: Artifact,
    endorsement: Endorsement
  ): Promise<ValidBundle>;
}

// Extracts the public key from a KeyMaterial. Returns either the public key
// or the certificate, depending on the type of key material.
function publicKey(key: KeyMaterial): string {
  switch (key.$case) {
    case 'publicKey':
      return key.publicKey;
    case 'x509Certificate':
      return key.certificate;
  }
}
