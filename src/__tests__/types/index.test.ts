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
import * as legacy from '../../types/bundle';
import {
  translateLegacyBundle,
  translateLegacyBundleJSON,
} from '../../types/index';
import bundles from '../__fixtures__/bundles/';

describe('translateLegacyBundleJSON', () => {
  it('should translate legacy bundle', () => {
    const legacyBundleJSON = bundles.dsse.valid.withSigningCert;
    const json = translateLegacyBundleJSON(legacyBundleJSON);

    expect(json).toBeDefined();
    expect(json.verificationMaterial.tlogEntries).toBeDefined();
    expect(json.verificationData).toBeUndefined();
  });
});

describe('translateLegacyBundle', () => {
  it('should trantlates the legacy bundle', () => {
    const legacyBundleJSON = bundles.dsse.valid.withSigningCert;
    const legacyBundle = legacy.Bundle.fromJSON(legacyBundleJSON);
    const bundle = translateLegacyBundle(legacyBundle);

    expect(bundle).toBeDefined();
    expect(bundle.verificationMaterial?.tlogEntries).toBeDefined();
    expect(bundle.verificationMaterial?.tlogEntries).toHaveLength(1);
  });
});
