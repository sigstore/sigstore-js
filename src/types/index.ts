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
import * as legacy from './bundle';
import * as sigstore from './sigstore';

// Convert from old bundle format to new one
// TODO: Remove this once we switched all code to use the new format
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function translateLegacyBundleJSON(json: any): any {
  const legacyBundle = legacy.Bundle.fromJSON(json);
  const bundle = translateLegacyBundle(legacyBundle);
  return sigstore.Bundle.toJSON(bundle);
}

// Convert from old bundle format to new one
// TODO: Remove this once we switched all code to use the new format
export function translateLegacyBundle(
  legacyBundle: legacy.Bundle
): sigstore.Bundle {
  let content: sigstore.Bundle['content'];

  // One of the values from the HashAlgorithm enum was removed in the new
  // version, so we need to unpack the "content" structure and ensure that
  // the value was not set to the removed value.
  if (legacyBundle.content?.$case === 'dsseEnvelope') {
    content = legacyBundle.content;
  } else if (legacyBundle.content?.$case === 'messageSignature') {
    content = {
      $case: 'messageSignature',
      messageSignature: {
        signature: legacyBundle.content.messageSignature.signature,
        messageDigest: legacyBundle.content.messageSignature.messageDigest
          ? {
              digest:
                legacyBundle.content.messageSignature.messageDigest?.digest,
              algorithm:
                legacyBundle.content.messageSignature.messageDigest
                  .algorithm === legacy.HashAlgorithm.SHA2_256
                  ? sigstore.HashAlgorithm.SHA2_256
                  : sigstore.HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED,
            }
          : undefined,
      },
    };
  }

  // Relocate the tlogEntries and timestampVerificationData fields from the
  // verificationData field to the verificationMaterial field.
  return {
    mediaType: legacyBundle.mediaType,
    content: content,
    verificationMaterial: {
      tlogEntries: legacyBundle.verificationData
        ? legacyBundle.verificationData.tlogEntries
        : [],
      timestampVerificationData:
        legacyBundle.verificationData?.timestampVerificationData,
      ...legacyBundle.verificationMaterial,
    },
  };
}
