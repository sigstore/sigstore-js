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
import type { TransparencyLogEntry } from '@sigstore/bundle';
import { VerificationError } from '../../../error';
import { verifyMerkleInclusion } from '../../../tlog/verify/merkle';

describe('verifyMerkleInclusion', () => {
  // Test data comes from https://rekor.sigstore.dev/api/v1/log/entries?logIndex=25591465
  const canonicalizedBody = Buffer.from(
    'eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7ImVudmVsb3BlIjp7InBheWxvYWRUeXBlIjoiYXBwbGljYXRpb24vdm5kLmluLXRvdG8ranNvbiIsInNpZ25hdHVyZXMiOlt7InB1YmxpY0tleSI6IkxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENrMUpTVU13VkVORFFXeGhaMEYzU1VKQlowbFZRMGxaYmpsclZWQkRTV2hqTVdKcFJFTTBhMlJQV1ROVGNXRm5kME5uV1VsTGIxcEplbW93UlVGM1RYY0tUbnBGVmsxQ1RVZEJNVlZGUTJoTlRXTXliRzVqTTFKMlkyMVZkVnBIVmpKTlVqUjNTRUZaUkZaUlVVUkZlRlo2WVZka2VtUkhPWGxhVXpGd1ltNVNiQXBqYlRGc1drZHNhR1JIVlhkSWFHTk9UV3BOZDA1cVNUVk5WR040VFVSVk1WZG9ZMDVOYWsxM1RtcEpOVTFVWTNsTlJGVXhWMnBCUVUxR2EzZEZkMWxJQ2t0dldrbDZhakJEUVZGWlNVdHZXa2w2YWpCRVFWRmpSRkZuUVVVelZVOVVZWGhKVW5sUFdHbHJOM1JCVFRKT01rcFNkV04zVG1aRmNYUXdRbkE1Tm1FS2VHd3hORUpOV0ZRMWR5OW1lVzAwWmtNd1JFUnZUazVyY0ZaWVVtZHFhMjkxTTBjeFpsa3dZV3RzY2xJclJpOWFWWEZQUTBGWVZYZG5aMFo0VFVFMFJ3cEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJWRUpuVGxaSVUxVkZSRVJCUzBKblozSkNaMFZHUWxGalJFRjZRV1JDWjA1V1NGRTBSVVpuVVZWWlRXbGxDa2xRVVhKWUwwdE5NM2xqTWtZeFNHRnhXSEZwTTJNMGQwaDNXVVJXVWpCcVFrSm5kMFp2UVZVek9WQndlakZaYTBWYVlqVnhUbXB3UzBaWGFYaHBORmtLV2tRNGQwaDNXVVJXVWpCU1FWRklMMEpDVlhkRk5FVlNXVzVLY0ZsWE5VRmFSMVp2V1ZjeGJHTnBOV3BpTWpCM1RFRlpTMHQzV1VKQ1FVZEVkbnBCUWdwQlVWRmxZVWhTTUdOSVRUWk1lVGx1WVZoU2IyUlhTWFZaTWpsMFRESjRkbG95YkhWTU1qbG9aRmhTYjAxRE5FZERhWE5IUVZGUlFtYzNPSGRCVVdkRkNrbEJkMlZoU0ZJd1kwaE5Oa3g1T1c1aFdGSnZaRmRKZFZreU9YUk1NbmgyV2pKc2RVd3lPV2hrV0ZKdlRVbEhTMEpuYjNKQ1owVkZRV1JhTlVGblVVTUtRa2gzUldWblFqUkJTRmxCTTFRd2QyRnpZa2hGVkVwcVIxSTBZMjFYWXpOQmNVcExXSEpxWlZCTE15OW9OSEI1WjBNNGNEZHZORUZCUVVkS1EwTk1lUXAxVVVGQlFrRk5RVko2UWtaQmFVRnphbTh6YTBvd1lYWlFkelUwY2tGVVNHNVNRelF6TkZKUVpFMHZlbTlCVldsdFRuZERSQ3MyZVZsUlNXaEJURXQ0Q2pGdWVsUk9NSGxEYTBKdVRUbFlTMVkyUVdSRGVVdFdkMmh2TjFKeU1GbEdORW95WldGclMweE5RVzlIUTBOeFIxTk5ORGxDUVUxRVFUSnJRVTFIV1VNS1RWRkVORzgwWVRoa2VraDNZbFIwTmpJMU5FazFXWHBETVVoWVJVSnRlazQwVkVoYVpGQnBMMlpZZFc1T2NXTTVMMjF2V0d0cWQxcExTSE5DWWtSV09RcElOVmxEVFZGRVRVRTNaemhQWldwSU5rMTNVa2xpVXk5WFVUTjFOM1ZWV21WYVNsRnFTMFJHWWpkTmJHTmxRbFI0SzBRdlQzTnFkVkpOTldwWWRtNWFDa1l5UmxaeVYxVTlDaTB0TFMwdFJVNUVJRU5GVWxSSlJrbERRVlJGTFMwdExTMD0iLCJzaWciOiJUVVZWUTBsUlJFNXBWWGxPZWxwc05pOU1iblJ4ZUdoNVRsZExUbkZJYm1aRFFrWnNWRWxCYjNKdFNtSnFXRWRqZVZGSlowOVFSM0ZNYm5wWFlWWlJWbk5KUlZwQ1MyNXJURzlWVGtJMlJIWkRVVGRxT0RaTVJIZ3dObE13ZEZrOSJ9XX0sImhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3OWJiMDRhN2VhMDA3M2FiN2VmY2NkYjlkOWM5NTQ0MWJiOWJkNjQ5ZGE5ZTc0YzNlNzkzMTVlZTk5NjFkYWE4In0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiOGE3NWY2YzhkYzRkOWY0MDcyODViYjQ5ZDNlMDE5YTVlNjY2ZjQzNDk5YzI3MDdkOTI4OWFhMjdjM2MyYTY3ZSJ9fX19',
    'base64'
  );
  const inclusionProof = {
    logIndex: '21428034',
    treeSize: '21476367',
    hashes: [
      Buffer.from(
        '19d3dbf73de6aefabc91f0b0e143b98aa85a09da0fe425ec5f1cd6d156f71618',
        'hex'
      ),
      Buffer.from(
        'd1142137fddf94069fea54345b912823d6b58b6c11988056581e14328cc1030f',
        'hex'
      ),
      Buffer.from(
        '93dc3b1aa26f0abe487597beae4e195e906e749e8e4ddeee27e79dbde5b91402',
        'hex'
      ),
      Buffer.from(
        '39f0b7d480d19cf281a3fd1bb9e22d2e00c4439872b4bbf93356761ff7924d01',
        'hex'
      ),
      Buffer.from(
        'c4dbc3de6933e3adec550dd14c7fee8959ae510524e8028c3e755c3c6b865be4',
        'hex'
      ),
      Buffer.from(
        'fb0c3969556c47a5da58cb9cd58de783f1d133f145b2a24ff6c7767ad0557b20',
        'hex'
      ),
      Buffer.from(
        '8a8f4d600381615d5a9ebc191241cffa65299e80a5f48562f63d72630aedf0c6',
        'hex'
      ),
      Buffer.from(
        '6e3cfb0b5ac7d32e7e58f51324748e12600d03fe293049fe36247fed3fb2fa65',
        'hex'
      ),
      Buffer.from(
        'ea20898f9069a9d85faf515f20b062b56b1ff4c1750ce4d741acead08b254b4a',
        'hex'
      ),
      Buffer.from(
        '3c0c2711b5709e116362413734eebf10b2dcd81cadd2325502254585f5408a93',
        'hex'
      ),
      Buffer.from(
        '293213bbbac895205eb11b6a4f905eeb2632182aa8022fc96c109d5fa9d9ea31',
        'hex'
      ),
      Buffer.from(
        'f6f08053bc2277b800e3bfbc74db76a24015f1f38a17e438fac9f3e3a49aa1d4',
        'hex'
      ),
      Buffer.from(
        '0be5c7bbcf481d1efcfc63a27fce447cf6345f7bb3155cf5de39de592c16d52d',
        'hex'
      ),
      Buffer.from(
        'f597f4bae8df3d6fc6eebfe3eabd7d393e08781f6f16b42398eca8512398fff1',
        'hex'
      ),
      Buffer.from(
        '4e35fcb3c0a59e7f329994002b38db35f5d511f499ba009e10b31f5d27563607',
        'hex'
      ),
      Buffer.from(
        '47044b7ac3aab820e44f0010538d7de71e17a11f4140cbbe9eeb37f78b77cc7d',
        'hex'
      ),
      Buffer.from(
        'a096e8b56b363e063fb47944b05535e10247eae804325cc5c5df3d024b61e9bf',
        'hex'
      ),
      Buffer.from(
        'ff41aa21106dbe03996b4335dd158c7ffafd144e45022193de19b2b9136c3e42',
        'hex'
      ),
      Buffer.from(
        'e6ebdeef2e23335d8d7049ba5a0049a90593efdfe9c1b4548946b44a19d7214f',
        'hex'
      ),
      Buffer.from(
        'dd51e840e892d70093ad7e1db1e2dea3d50334c7345d360e444d22fc49ed9f5e',
        'hex'
      ),
      Buffer.from(
        'ad712c98424de0f1284d4f144b8a95b5d22c181d4c0a246518e7a9a220bdf643',
        'hex'
      ),
    ],
    rootHash: Buffer.from(
      'd5c395a44b9537f8fa2524a6e93071969dd475ac40e87e2b1231b2aebd9a138b',
      'hex'
    ),
  };

  describe('when the inclusion proof is valid', () => {
    const entry = {
      canonicalizedBody,
      inclusionProof,
    } as TransparencyLogEntry;

    it('returns true', () => {
      expect(verifyMerkleInclusion(entry)).toBe(true);
    });
  });

  describe('when the entry does NOT match the inclusion proof', () => {
    const invalidEntry = {
      canonicalizedBody: Buffer.from('invalid'),
      inclusionProof,
    } as TransparencyLogEntry;

    it('returns false', () => {
      expect(verifyMerkleInclusion(invalidEntry)).toBe(false);
    });
  });

  describe('when the log index is invalid', () => {
    const invalidEntry = {
      canonicalizedBody,
      inclusionProof: { ...inclusionProof, logIndex: '-1' },
    } as TransparencyLogEntry;

    it('throws an error', () => {
      expect(() => verifyMerkleInclusion(invalidEntry)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the entry does NOT contain an inclusion proof', () => {
    const invalidEntry = {
      canonicalizedBody,
      inclusionProof: undefined,
    } as TransparencyLogEntry;

    it('throws an error', () => {
      expect(() => verifyMerkleInclusion(invalidEntry)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the inclusion proof log index is greather than the tree size', () => {
    const invalidEntry = {
      canonicalizedBody,
      inclusionProof: { ...inclusionProof, treeSize: '99', logIndex: '100' },
    } as TransparencyLogEntry;

    it('throws an error true', () => {
      expect(() => verifyMerkleInclusion(invalidEntry)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the inclusion proof is missing hashes', () => {
    const invalidEntry = {
      canonicalizedBody: Buffer.from('foo'),
      inclusionProof: {
        ...inclusionProof,
        hashes: inclusionProof.hashes.slice(0, 1),
      },
    } as TransparencyLogEntry;

    it('throws an error true', () => {
      expect(() => verifyMerkleInclusion(invalidEntry)).toThrow(
        VerificationError
      );
    });
  });
});
