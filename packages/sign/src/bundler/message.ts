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
import { Artifact, BaseBundleBuilder, BundleBuilderOptions } from './base';
import { toMessageSignatureBundle } from './bundle';

import type { BundleWithMessageSignature } from '@sigstore/bundle';
import type { Signature } from '../signer';

// BundleBuilder implementation for raw message signatures
export class MessageSignatureBundleBuilder extends BaseBundleBuilder<BundleWithMessageSignature> {
  constructor(options: BundleBuilderOptions) {
    super(options);
  }

  protected override async package(
    artifact: Artifact,
    signature: Signature
  ): Promise<BundleWithMessageSignature> {
    return toMessageSignatureBundle(artifact, signature);
  }
}
