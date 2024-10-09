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
import { dsse } from '../util';
import { Artifact, BaseBundleBuilder, BundleBuilderOptions } from './base';
import { toDSSEBundle } from './bundle';

import type { BundleWithDsseEnvelope } from '@sigstore/bundle';
import type { Signature } from '../signer';

type DSSEBundleBuilderOptions = BundleBuilderOptions & {
  // When set to true, the bundle verification material will use the
  // certificate field instead of the x509CertificateChain field.
  // When undefied/false, a v0.2 bundle will be created.
  certificateChain?: boolean;
};

// BundleBuilder implementation for DSSE wrapped attestations
export class DSSEBundleBuilder extends BaseBundleBuilder<BundleWithDsseEnvelope> {
  private certificateChain?: boolean;
  constructor(options: DSSEBundleBuilderOptions) {
    super(options);
    this.certificateChain = options.certificateChain ?? false;
  }

  // DSSE requires the artifact to be pre-encoded with the payload type
  // before the signature is generated.
  protected override async prepare(artifact: Artifact): Promise<Buffer> {
    const a = artifactDefaults(artifact);
    return dsse.preAuthEncoding(a.type, a.data);
  }

  // Packages the artifact and signature into a DSSE bundle
  protected override async package(
    artifact: Artifact,
    signature: Signature
  ): Promise<BundleWithDsseEnvelope> {
    return toDSSEBundle(
      artifactDefaults(artifact),
      signature,
      this.certificateChain
    );
  }
}

// Defaults the artifact type to an empty string if not provided
function artifactDefaults(artifact: Artifact): Required<Artifact> {
  return {
    ...artifact,
    type: artifact.type ?? '',
  };
}
