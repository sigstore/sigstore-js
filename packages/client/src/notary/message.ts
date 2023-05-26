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
import { toMessageSignatureBundle } from './bundle';
import { Artifact, BaseNotary, NotaryOptions } from './notary';

import type { Endorsement } from '../signatory';
import type { Bundle } from '../types/sigstore';

// Notary implementation for raw message signatures
export class MessageNotary extends BaseNotary {
  constructor(options: NotaryOptions) {
    super(options);
  }

  override async package(
    artifact: Artifact,
    endorsement: Endorsement
  ): Promise<Bundle> {
    return toMessageSignatureBundle(artifact, endorsement);
  }
}
