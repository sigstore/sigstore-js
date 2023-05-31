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
import { toDSSEBundle } from './bundle';
import { Artifact, BaseNotary, NotaryOptions } from './notary';

import type * as sigstore from '@sigstore/bundle';
import type { Endorsement } from '../signatory';

// Notary implementation for DSSE wrapped attestations
export class DSSENotary extends BaseNotary {
  constructor(options: NotaryOptions) {
    super(options);
  }

  // DSSE requires the artifact to be pre-encoded with the payload type
  // before the signature is generated.
  protected override async prepare(artifact: Artifact): Promise<Buffer> {
    const a = artifactDefaults(artifact);
    return dsse.preAuthEncoding(a.type, a.data);
  }

  // Packages the artifact and endorsement into a DSSE bundle
  protected override async package(
    artifact: Artifact,
    endorsement: Endorsement
  ): Promise<sigstore.Bundle> {
    return toDSSEBundle(artifactDefaults(artifact), endorsement);
  }
}

// Defaults the artifact type to an empty string if not provided
function artifactDefaults(artifact: Artifact): Required<Artifact> {
  return {
    ...artifact,
    type: artifact.type ?? '',
  };
}
