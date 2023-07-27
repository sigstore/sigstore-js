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
import type { TLogEntryWithInclusionProof } from '@sigstore/bundle';
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
    } as TLogEntryWithInclusionProof;

    it('returns true', () => {
      expect(verifyMerkleInclusion(entry)).toBe(true);
    });
  });

  describe('when the entry does NOT match the inclusion proof', () => {
    const invalidEntry = {
      canonicalizedBody: Buffer.from('invalid'),
      inclusionProof,
    } as TLogEntryWithInclusionProof;

    it('returns false', () => {
      expect(verifyMerkleInclusion(invalidEntry)).toBe(false);
    });
  });

  describe('when the log index is invalid', () => {
    const invalidEntry = {
      canonicalizedBody,
      inclusionProof: { ...inclusionProof, logIndex: '-1' },
    } as TLogEntryWithInclusionProof;

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
    } as TLogEntryWithInclusionProof;

    it('throws an error', () => {
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
    } as TLogEntryWithInclusionProof;

    it('throws an error', () => {
      expect(() => verifyMerkleInclusion(invalidEntry)).toThrow(
        VerificationError
      );
    });
  });

  describe('when all of the hashes are on the right side of the tree', () => {
    // Test data comes from https://rekor.sigstore.dev/api/v1/log/entries?logIndex=28908823
    const canonicalizedBody = Buffer.from(
      'eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7ImVudmVsb3BlIjp7InBheWxvYWRUeXBlIjoiYXBwbGljYXRpb24vdm5kLmluLXRvdG8ranNvbiIsInNpZ25hdHVyZXMiOlt7InB1YmxpY0tleSI6IkxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENrMUpTVWxOUkVORFFqZGxaMEYzU1VKQlowbFZVbEl2WTFaeVZ6bDFiRWRYVFUxRllXcE5jM1YyVFZKb1kxVkJkME5uV1VsTGIxcEplbW93UlVGM1RYY0tUbnBGVmsxQ1RVZEJNVlZGUTJoTlRXTXliRzVqTTFKMlkyMVZkVnBIVmpKTlVqUjNTRUZaUkZaUlVVUkZlRlo2WVZka2VtUkhPWGxhVXpGd1ltNVNiQXBqYlRGc1drZHNhR1JIVlhkSWFHTk9UV3BOZDA1NlNUTk5SRUY1VFVSUk5GZG9ZMDVOYWsxM1RucEpNMDFFUVhwTlJGRTBWMnBCUVUxR2EzZEZkMWxJQ2t0dldrbDZhakJEUVZGWlNVdHZXa2w2YWpCRVFWRmpSRkZuUVVWdk9IQlRaVE5KYzNOUVNsUm9OSGQ1YjBSeGVXSkJNWEZYZFdGNVl6Smxlbk51YVc4S2EwMUhXR2xRWjNCTWNuWnhaalpYZGpWS2JFUkRObHBUZG1vNGFVWmFRekJyUTBSV1ZtVkZRemRaWVdJMk1sbFFaVFpQUTBKMFdYZG5aMkpUVFVFMFJ3cEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJWRUpuVGxaSVUxVkZSRVJCUzBKblozSkNaMFZHUWxGalJFRjZRV1JDWjA1V1NGRTBSVVpuVVZWVE4wZE9DblJaUVZkUWFtaHpPVEJrY25aWU1qUnNRMFUzUXl0UmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZVek9WQndlakZaYTBWYVlqVnhUbXB3UzBaWGFYaHBORmtLV2tRNGQyZGhWVWRCTVZWa1JWRkZRaTkzVTBKdGFrTkNiRFJoUW14SGFEQmtTRUo2VDJrNGRsb3liREJoU0ZacFRHMU9kbUpUT1hwaFYyUjZaRWM1ZVFwYVV6RnFZakkxYldJelNuUlpWelZxV2xNNWJHVklVbmxhVnpGc1lraHJkRnBIUm5WYU1sWjVZak5XZWt4WVFqRlpiWGh3V1hreGRtRlhVbXBNVjBwc0NsbFhUblppYVRoMVdqSnNNR0ZJVm1sTU0yUjJZMjEwYldKSE9UTmplVGxzWlVoU2VWcFhNV3hpU0d0MFdrZEdkVm95Vm5saU0xWjZURmM1Y0ZwSFRYUUtXVzFXYUZreU9YVk1ibXgwWWtWQ2VWcFhXbnBNTW1oc1dWZFNla3d5TVdoaFZ6UjNUMUZaUzB0M1dVSkNRVWRFZG5wQlFrRlJVWEpoU0ZJd1kwaE5OZ3BNZVRrd1lqSjBiR0pwTldoWk0xSndZakkxZWt4dFpIQmtSMmd4V1c1V2VscFlTbXBpTWpVd1dsYzFNRXh0VG5aaVZFRm1RbWR2Y2tKblJVVkJXVTh2Q2sxQlJVTkNRa1l6WWpOS2NscHRlSFprTVRscllWaE9kMWxZVW1waFJFRXlRbWR2Y2tKblJVVkJXVTh2VFVGRlJFSkRhR2hhYW1NMFRsZEpNbHBFVG1rS1RVZGFhRTFIVFhkWlYwVjRUWHBCTVZwdFJteGFWR1JxV2xSWmQwMTZXbXhQUjFFMVRVZE5NRTFETUVkRGFYTkhRVkZSUW1jM09IZEJVVkZGU0RCV05BcGtTRXBzWWxkV2MyVlRRbXRaVnpWdVdsaEtkbVJZVFdkVU1HeEZVWGxDYVZwWFJtcGlNalIzVTFGWlMwdDNXVUpDUVVkRWRucEJRa0pSVVRkak1teHVDbU16VW5aamJWVjBXVEk1ZFZwdE9YbGlWMFoxV1RKVmRscFlhREJqYlZaMFdsZDROVXhYVW1oaWJXUnNZMjA1TVdONU1YZGtWMHB6WVZkTmRHSXliR3NLV1hreGFWcFhSbXBpTWpSM1NGRlpTMHQzV1VKQ1FVZEVkbnBCUWtKblVWQmpiVlp0WTNrNWIxcFhSbXRqZVRsMFdWZHNkVTFFYzBkRGFYTkhRVkZSUWdwbk56aDNRVkZuUlV4UmQzSmhTRkl3WTBoTk5reDVPVEJpTW5Sc1ltazFhRmt6VW5CaU1qVjZURzFrY0dSSGFERlpibFo2V2xoS2FtSXlOVEJhVnpVd0NreHRUblppVkVOQ2NHZFpTMHQzV1VKQ1FVZEVkbnBCUWtOUlUwSnNkM2xDYkVkb01HUklRbnBQYVRoMldqSnNNR0ZJVm1sTWJVNTJZbE01ZW1GWFpIb0taRWM1ZVZwVE1XcGlNalZ0WWpOS2RGbFhOV3BhVXpsc1pVaFNlVnBYTVd4aVNHdDBXa2RHZFZveVZubGlNMVo2VEZoQ01WbHRlSEJaZVRGMllWZFNhZ3BNVjBwc1dWZE9kbUpwT0hWYU1td3dZVWhXYVV3elpIWmpiWFJ0WWtjNU0yTjVPV3hsU0ZKNVdsY3hiR0pJYTNSYVIwWjFXakpXZVdJelZucE1Wemx3Q2xwSFRYUlpiVlpvV1RJNWRVeHViSFJpUlVKNVdsZGFla3d5YUd4WlYxSjZUREl4YUdGWE5IZFBRVmxMUzNkWlFrSkJSMFIyZWtGQ1EyZFJjVVJEYUdnS1dtcGpORTVYU1RKYVJFNXBUVWRhYUUxSFRYZFpWMFY0VFhwQk1WcHRSbXhhVkdScVdsUlpkMDE2V214UFIxRTFUVWROTUUxQ01FZERhWE5IUVZGUlFncG5OemgzUVZGelJVUjNkMDVhTW13d1lVaFdhVXhYYUhaak0xSnNXa1JDWlVKbmIzSkNaMFZGUVZsUEwwMUJSVTFDUmtGTlZHMW9NR1JJUW5wUGFUaDJDbG95YkRCaFNGWnBURzFPZG1KVE9YcGhWMlI2WkVjNWVWcFRNV3BpTWpWdFlqTktkRmxYTldwYVV6bHNaVWhTZVZwWE1XeGlTR3QwV2tkR2RWb3lWbmtLWWpOV2VreFlRakZaYlhod1dYa3hkbUZYVW1wTVYwcHNXVmRPZG1KcVFUUkNaMjl5UW1kRlJVRlpUeTlOUVVWT1FrTnZUVXRIUm0xT2VtY3hXV3BhYXdwTk1rbDNXbTFGZDFsNlFtaFpWRVY2VFVSV2JWbFhWbXhPTWs1c1RtcEJlazV0VlRSYVJHdDNXWHBSZDBoM1dVdExkMWxDUWtGSFJIWjZRVUpFWjFGU0NrUkJPWGxhVjFwNlRESm9iRmxYVW5wTU1qRm9ZVmMwZDBkUldVdExkMWxDUWtGSFJIWjZRVUpFZDFGTVJFRnJNazE2U1RGUFZGazBUMVJqZDA1M1dVc0tTM2RaUWtKQlIwUjJla0ZDUlVGUmNFUkRaRzlrU0ZKM1kzcHZka3d5WkhCa1IyZ3hXV2sxYW1JeU1IWmpNbXh1WXpOU2RtTnRWWFJaTWpsMVdtMDVlUXBpVjBaMVdUSlZkMGRSV1V0TGQxbENRa0ZIUkhaNlFVSkZVVkZNUkVGcmVFMTZSVFJOUkZFeFRtcE5kMmRoV1VkRGFYTkhRVkZSUW1jM09IZEJVa2xGQ21kYVkwMW5XbEp2WkVoU2QyTjZiM1pNTW1Sd1pFZG9NVmxwTldwaU1qQjJZekpzYm1NelVuWmpiVlYwV1RJNWRWcHRPWGxpVjBaMVdUSlZkbHBZYURBS1kyMVdkRnBYZURWTVYxSm9ZbTFrYkdOdE9URmplVEYzWkZkS2MyRlhUWFJpTW14cldYa3hhVnBYUm1waU1qUjJURzFrY0dSSGFERlphVGt6WWpOS2NncGFiWGgyWkROTmRscFlhREJqYlZaMFdsZDROVXhYVW1oaWJXUnNZMjA1TVdONU1YWmhWMUpxVEZkS2JGbFhUblppYVRVMVlsZDRRV050Vm0xamVUbHZDbHBYUm10amVUbDBXVmRzZFUxRVowZERhWE5IUVZGUlFtYzNPSGRCVWsxRlMyZDNiMWxYV1ROUFJGWnBUbTFSZWxscVFtMVpWRUpxVFVkR2FFMVVUWGNLVGxkYWFGcFhWVE5aTWxVeVRVUk5NbHBVYUd0UFZFSnFUa1JCYUVKbmIzSkNaMFZGUVZsUEwwMUJSVlZDUWsxTlJWaGtkbU50ZEcxaVJ6a3pXREpTY0Fwak0wSm9aRWRPYjAxSlIwSkNaMjl5UW1kRlJVRlpUeTlOUVVWV1FraE5UV05YYURCa1NFSjZUMms0ZGxveWJEQmhTRlpwVEcxT2RtSlRPWHBoVjJSNkNtUkhPWGxhVXpGcVlqSTFiV0l6U25SWlZ6VnFXbE01YkdWSVVubGFWekZzWWtocmRGcEhSblZhTWxaNVlqTldla3hZUWpGWmJYaHdXWGt4ZG1GWFVtb0tURmRLYkZsWFRuWmlhVGxvV1ROU2NHSXlOWHBNTTBveFltNU5kazVVV1ROT1JHczBUbXBKZWs1RE9XaGtTRkpzWWxoQ01HTjVPSGhOUWxsSFEybHpSd3BCVVZGQ1p6YzRkMEZTV1VWRFFYZEhZMGhXYVdKSGJHcE5TVWRMUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpJZDBWbFowSTBRVWhaUVROVU1IZGhjMkpJQ2tWVVNtcEhValJqYlZkak0wRnhTa3RZY21wbFVFc3pMMmcwY0hsblF6aHdOMjgwUVVGQlIwcHNUR2N6UzJkQlFVSkJUVUZTZWtKR1FXbEZRWFJKTDNrS2NtWkZVVmc0T0d3MmFETXpaWEk1ZVdSWWNVZHpWalZYVkM4eVZrSmlUbFF4U1RaRVVtZDNRMGxEZDNkVWJrSlJNRmh5WVhFeFREQlFNVmxRY1U1UGFncDVWMmN2U0hsVE1uazJSRmx6Tlc0NVkwUlpRazFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbU5CVFVkUlEwMUJLMFZKVVVnelVFUkhUalZ4UlU1blRXVk1DbFZ0Y1RCbllXa3dNekEzUkhSVFUxTXdZbGRHWTJSdmVtMVVibGt2ZEdSYWVVVXdORXBtUlRoeU1YY3lRbEZKZDFGbGJXZFdNV2h2VVRZM1pWZDBiSFlLTTNWTVVEaHJUbWRNYjAxNUx6RnZWWE5GZUVaQ1V6Vm5iRFYyZEVNelkzTkZZek0xYzBrcllqTTVlblUwYjA4ckNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwPSIsInNpZyI6IlRVVlpRMGxSUkVadGNGbGtlRFpHV2pWc1ZXTjJUM3BLYlRRdlNHSmhTSHBoUkdaRFQyWXpSM0V5YUhaVFVISkVkWGRKYUVGUVkwZFdkVWxaYW1GaVozVjBUVEpuZDNKM1FWbFVkVU00ZG5oNlZIbFZLMUEyUzFGc1NYcEJXR3RSIn1dfSwiaGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjNmYWVlNzk1YzNlNmU1ZGMyZWI0YTZkYmQxNjVjYTY5MWU5MjAwNTMwNDk5YWMwMjI1MmZjODMwZmNjMzUyMTUifSwicGF5bG9hZEhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJhMGNmYzcxMjcxZDZlMjc4ZTU3Y2QzMzJmZjk1N2MzZjcwNDNmZGRhMzU0YzRjYmIxOTBhMzBkNTZlZmEwMWJmIn19fX0=',
      'base64'
    );
    const inclusionProof = {
      logIndex: '24745392',
      treeSize: '24745393',
      hashes: [
        Buffer.from(
          '87f268d27f75324b31facf61ad94d5af2a42875f8bf0822764c60e01eda28ed3',
          'hex'
        ),
        Buffer.from(
          '60280a666bb43645f3e18b3d8a11ad9ee6d52d5c89f00159cf4b6f33915abf7c',
          'hex'
        ),
        Buffer.from(
          '82fafcc84770b9c63ac5a17c0c9c89feaa1ae395ece0bfe41275a65c337e504d',
          'hex'
        ),
        Buffer.from(
          'b12f37b6c04f69e3e7ab4802c235401b51c2a3ec8926fd3c6113476f13a9fc10',
          'hex'
        ),
        Buffer.from(
          '27e4fcdafa8179ea163130b001c73898048cd5b83661ea964db1b933c1243448',
          'hex'
        ),
        Buffer.from(
          '7bee8b5d585295de499a4bda0d0050bcb25bc743ddc37567c03bba9fa3d2731e',
          'hex'
        ),
        Buffer.from(
          'bd92d1f2e120adecf547e8c273a1531470af6c7e370f442a1582bb7eba3fa835',
          'hex'
        ),
        Buffer.from(
          '21c262c7b865f36cdbf34276624618bb4f527cdd42ab7e005deb0d4d94643c27',
          'hex'
        ),
        Buffer.from(
          'b27166ad226c74e433d737bdabaec10b8f6d413fc35f3e3265132360f5cd3b8a',
          'hex'
        ),
        Buffer.from(
          'd1ab30cb7ad6b58d34cbdb9d9c4765f864f52c10a8d38534425c1423964dd870',
          'hex'
        ),
        Buffer.from(
          '65dca74f677817734540d06eac50da641a183154636d08e54e748bd612faefeb',
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
        '5efa9dadd1af89aee9f70c8deb2d537b4c1add01f2f877ef83ebf7f839100832',
        'hex'
      ),
    };

    describe('when the inclusion proof is valid', () => {
      const entry = {
        canonicalizedBody,
        inclusionProof,
      } as TLogEntryWithInclusionProof;

      it('returns true', () => {
        expect(verifyMerkleInclusion(entry)).toBe(true);
      });
    });
  });
});
