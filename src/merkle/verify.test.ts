/*
Copyright 2022 GitHub, Inc

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

import { verifyInclusion } from './verify';
import { Hasher } from './digest';

describe('verifyInclusion', () => {
  const defaultHasher = new Hasher();

  // Test data comes from https://rekor.sigstore.dev/api/v1/log/entries?logIndex=3056587
  const entry =
    'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI0OGQ5OTkyNjBkZmY4ZDgzNGY4MWM4NWE3NGY1MDk1YWY4ZWRlNTM5ZWEzYWVhMTk5NTc4N2M0NTU1YzZiZTQ3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJUURDRnBjaHVyQTNTWVNFMTJHTG9qUjRZRmR5RFpkaU9IbkppYVdLRENiVW53SWdHSnJRUm5qcm9xUmtuRiszRUdqaHhqaURUZDhURXB2MTVmZkRBR2Z6enVVPSIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRXVmpZWFVyV1daTlJsZFpjazV0ZDFreldVaE5kM0E0VlUwMU1RcHhaV1o1ZG1oWmNqSnhaV0pLV0ZCdFdFY3hWM0JpYkdwWFkyYzVaekZHVDJoUWFXVjVPVWh6VEVsdGFERnJWMlJqYkhjdlkzcERWMUYzUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19';
  const entryBytes = Buffer.from(entry, 'base64');

  const hashes = [
    '6f6ad87e72762b653c96db394eadcb58a8bbce16ba72fd3d1ad56421baefd0af',
    '2fa68c2f97cdf8257b0e8103d10ab6320c5007099c8f9e2c2196db634dc364f5',
    '9f8f947be87b4f343a0ad1a4835cabd0c744eff2a51b852057e8459e2bb55a56',
    '336e1fc366c19dd34250e10baea5ef74caa0a5b7db0ae92047fcda8067c0385f',
    '5da501f1e7f45fe63af0b09373b4f5578b3899d3fc6e0ec7262387d2975eb22c',
    '490b00a963228e7a8f70762d4856eeeb8280413e1d1cb7fb4e9683e223b5f6ba',
    '075e588755235f14fddd7190ac9347b6ec045ce4c88a0794ce193cbfe3d60142',
    '167fe9d15fd6a3de12ae2747785e23c9425bf677c7fd957976cae3e27b6d9bd1',
    'eee183886501e85197c62c6c0d371e479115f71a50618d8552b73b228717a5ae',
    'ef118b4a9e69d9000c48515d7e2f30ce606197d21e6bacc82fd7a61c48a67507',
    'bd0cbc5a454654ff88d2e08e3c443204308e423834e0fed2481b847da5d2dfcf',
    'cec90b763ab869bc411f51ed8f4206b4d051c9502533f2638b15277fd2ae5e9e',
    '4e2d269ec9ef9d4e9270c482b70a64e75d84f850902b5e5e65acd14844cf659b',
    'd63d28e2b4a9476ea2df69f03be3e9dd453c2232ed172e5f79487a9e60711f51',
    '599040ed55824445153996171c1045d696176b6a252159aaa3630c033b45e70c',
    '860efc785c66773fe35db221860cfb482dfe0a6bfe602aaade78149084c9ab86',
    '39da4af7f0fbe095e6bc78c146ad59c70881d3fcb22e90c7675dee5e6736bc76',
    '806e7153f439cdb4558d7ac89defb0e17aa9742e888cb660774b94b5399c3322',
    'efb36cfc54705d8cd921a621a9389ffa03956b15d68bfabadac2b4853852079b',
  ];
  const proof = hashes.map((hash) => Buffer.from(hash, 'hex'));

  const rootHash =
    '8326106075b643a01711dddf32e9b361b475ca21e9d81afec867a3c6a3dbb55c';
  const root = Buffer.from(rootHash, 'hex');

  const index = BigInt(3056587);
  const size = BigInt(3063448);

  describe('when everything matches perfectly', () => {
    it('returns true', () => {
      const leafHash = defaultHasher.hashLeaf(entryBytes);

      expect(
        verifyInclusion(defaultHasher, index, size, leafHash, proof, root)
      ).toBe(true);
    });
  });

  describe('when the leaf hash is incorrect', () => {
    it('returns false', () => {
      const leafHash = defaultHasher.hashLeaf(Buffer.from('wrong'));

      expect(
        verifyInclusion(defaultHasher, index, size, leafHash, proof, root)
      ).toBe(false);
    });
  });

  describe('when the proof is missing hashes', () => {
    it('returns false', () => {
      const leafHash = defaultHasher.hashLeaf(entryBytes);

      expect(() => {
        verifyInclusion(
          defaultHasher,
          index,
          size,
          leafHash,
          proof.slice(2),
          root
        );
      }).toThrow('invalid proof length');
    });
  });
});
