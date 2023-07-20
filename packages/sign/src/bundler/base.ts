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
import type {
  Bundle,
  RFC3161SignedTimestamp,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type { KeyMaterial, Signature, Signer } from '../signer';
import type { Witness } from '../witness';

export interface BundleBuilderOptions {
  signer: Signer;
  witnesses: Witness[];
}

// Representation of the artifact to be signed. Includes the raw bytes of the
// artifact and an optional MIME type.
export interface Artifact {
  data: Buffer;
  type?: string;
}

// Interface for bundler implementations. A bundler is responsible for signing
// and witnessing an artifact.
export interface BundleBuilder {
  create: (artifact: Artifact) => Promise<Bundle>;
}

// BaseBundleBuilder is a base class for BundleBuilder implementations. It
// provides a the basic wokflow for signing and witnessing an artifact.
// Subclasses must implement the `package` method to assemble a valid bundle
// with the generated signature and verification material.
export abstract class BaseBundleBuilder implements BundleBuilder {
  protected signer: Signer;
  private witnesses: Witness[];

  constructor(options: BundleBuilderOptions) {
    this.signer = options.signer;
    this.witnesses = options.witnesses;
  }

  // Executes the signing/witnessing process for the given artifact.
  public async create(artifact: Artifact): Promise<Bundle> {
    const signature = await this.prepare(artifact).then((blob) =>
      this.signer.sign(blob)
    );
    const bundle = await this.package(artifact, signature);

    // Invoke all of the witnesses in parallel
    const verificationMaterials = await Promise.all(
      this.witnesses.map((witness) =>
        witness.testify(bundle.content, publicKey(signature.key))
      )
    );

    // Collect the verification material from all of the witnesses
    const tlogEntryList: TransparencyLogEntry[] = [];
    const timestampList: RFC3161SignedTimestamp[] = [];

    verificationMaterials.forEach(({ tlogEntries, rfc3161Timestamps }) => {
      tlogEntryList.push(...(tlogEntries ?? []));
      timestampList.push(...(rfc3161Timestamps ?? []));
    });

    // Merge the collected verification material into the bundle
    bundle.verificationMaterial.tlogEntries = tlogEntryList;
    bundle.verificationMaterial.timestampVerificationData = {
      rfc3161Timestamps: timestampList,
    };

    return bundle;
  }

  // Override this function to apply any pre-signing transformations to the
  // artifact. The returned buffer will be signed by the signer. The default
  // implementation simply returns the artifact data.
  protected async prepare(artifact: Artifact): Promise<Buffer> {
    return artifact.data;
  }

  // Override this function to package the artifact and signature into a
  // bundle. Any verification material from the configured witnesses will be
  // merged into the bundle.
  protected abstract package(
    artifact: Artifact,
    signature: Signature
  ): Promise<Bundle>;
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
