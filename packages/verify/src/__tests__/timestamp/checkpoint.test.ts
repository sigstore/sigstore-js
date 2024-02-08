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
import { crypto } from '@sigstore/core';
import { fromPartial } from '@total-typescript/shoehorn';
import { VerificationError } from '../../error';
import { verifyCheckpoint } from '../../timestamp/checkpoint';

import type { TLogEntryWithInclusionProof } from '@sigstore/bundle';
import type { TLogAuthority } from '../../trust';

describe('verifyCheckpoint', () => {
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.hash(keyBytes);

  const tlogInstance: TLogAuthority = {
    publicKey: crypto.createPublicKey(keyBytes),
    logID: keyID,
    validFor: { start: new Date('2000-01-01'), end: new Date('2100-01-01') },
  };

  const tlogs = [tlogInstance];

  const checkpoint =
    'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n';

  const inclusionProof: TLogEntryWithInclusionProof['inclusionProof'] =
    fromPartial({
      checkpoint: { envelope: checkpoint },
      rootHash: Buffer.from(
        'rxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=',
        'base64'
      ),
    });

  const entry: TLogEntryWithInclusionProof = fromPartial({
    inclusionProof: inclusionProof,
    integratedTime: '1688058655',
  });

  describe('when the entry has a valid checkpoint', () => {
    it('does NOT throw an error', () => {
      expect(verifyCheckpoint(entry, tlogs)).toBeUndefined();
    });
  });

  describe('when the checkpoint has no separator', () => {
    const entryWithInvalidCheckpoint: TLogEntryWithInclusionProof = fromPartial(
      {
        inclusionProof: {
          checkpoint: { envelope: 'rekor.sigstore.dev - 2605736670972794746' },
        },
      }
    );

    it('throws a VerificationError', () => {
      expect(() =>
        verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when the checkpoint signature is malformed', () => {
    const entryWithInvalidCheckpoint: TLogEntryWithInclusionProof = fromPartial(
      {
        inclusionProof: {
          checkpoint: {
            envelope:
              'rekor.sigstore.dev - 2605736670972794746\n\n— rekor.sigstore.dev foo\n',
          },
        },
      }
    );

    it('throws a VerificationError', () => {
      expect(() =>
        verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when the checkpoint has no signature', () => {
    const entryWitInvalidCheckpoint: TLogEntryWithInclusionProof = fromPartial({
      inclusionProof: {
        checkpoint: {
          envelope: 'rekor.sigstore.dev - 2605736670972794746\n\n',
        },
      },
    });

    it('throws a VerificationError', () => {
      expect(() =>
        verifyCheckpoint(entryWitInvalidCheckpoint, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when the checkpoint header is too short', () => {
    const entryWithInvalidCheckpoint: TLogEntryWithInclusionProof = fromPartial(
      {
        inclusionProof: {
          checkpoint: {
            envelope:
              'rekor.sigstore.dev\n\n— rekor.sigstore.dev wNI9ajBFAiEAu\n',
          },
        },
      }
    );

    it('throws a VerificationError', () => {
      expect(() =>
        verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when the checkpoint origin is empty', () => {
    const entryWithInvalidCheckpoint: TLogEntryWithInclusionProof = fromPartial(
      {
        inclusionProof: {
          checkpoint: {
            envelope: '\n1\nB\nC\n\n— rekor.sigstore.dev wNI9ajBFAiEAu\n',
          },
        },
      }
    );

    it('throws a VerificationError', () => {
      expect(() =>
        verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when the entry checkpoint has the wrong root hash', () => {
    const entry: TLogEntryWithInclusionProof = fromPartial({
      inclusionProof: { ...inclusionProof, rootHash: Buffer.from('foo') },
      integratedTime: '1688058655',
    });

    it('throws an error', () => {
      expect(() => verifyCheckpoint(entry, tlogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROOF_ERROR'
      );
    });
  });

  describe('when the entry checkpoint has a bad signature', () => {
    const badSignatureCheckpoint =
      'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own\n';

    const entryWithBadCheckpointSig: TLogEntryWithInclusionProof = fromPartial({
      inclusionProof: {
        ...inclusionProof,
        checkpoint: { envelope: badSignatureCheckpoint },
      },
    });

    it('throws an error', () => {
      expect(() =>
        verifyCheckpoint(entryWithBadCheckpointSig, tlogs)
      ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
    });
  });

  describe('when there is no transparency log with the given key ID', () => {
    const checkpointWithBadKeyHint =
      'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev xNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n';
    const entryWithBadLogID: TLogEntryWithInclusionProof = fromPartial({
      inclusionProof: {
        ...inclusionProof,
        checkpoint: { envelope: checkpointWithBadKeyHint },
      },
    });

    it('throws an error', () => {
      expect(() => verifyCheckpoint(entryWithBadLogID, tlogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROOF_ERROR'
      );
    });
  });

  describe('when key start time is after the entry time', () => {
    const invalidTLogs = [
      {
        ...tlogInstance,
        validFor: {
          start: new Date('2099-01-01'),
          end: new Date('2100-01-01'),
        },
      },
    ];

    it('throws an error', () => {
      expect(() => verifyCheckpoint(entry, invalidTLogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROOF_ERROR'
      );
    });
  });

  describe('when key is expired at the entry time', () => {
    const invalidTLogs = [
      {
        ...tlogInstance,
        validFor: {
          start: new Date('2000-01-01'),
          end: new Date('2001-01-01'),
        },
      },
    ];

    it('throws an error', () => {
      expect(() => verifyCheckpoint(entry, invalidTLogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROOF_ERROR'
      );
    });
  });

  describe('when there is a valid checkpoint with no timestamp', () => {
    // Using a real checkpoint from Rekor staging instance (log index 22781754)
    // At the time this test was added, only the staging instance was generating
    // checkpoints w/o the timestamp field.
    const keyBytes = Buffer.from(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==',
      'base64'
    );
    const keyID = crypto.hash(keyBytes);

    const tlogInstance: TLogAuthority = {
      publicKey: crypto.createPublicKey(keyBytes),
      logID: keyID,
      validFor: { start: new Date('2000-01-01'), end: new Date('2100-01-01') },
    };

    const tlogs = [tlogInstance];

    const checkpoint =
      'rekor.sigstage.dev - 8050909264565447525\n23003647\nWBwYpazawqUG5iErvDptvf7mpt84WIpmm+zfshgHhJs=\n\n— rekor.sigstage.dev 0y8wozBGAiEA2kq45YWfHHiDCJHH2+m9l+TVMtPBpOVu+VtVaj62V2MCIQDflbM2N7M/JTIV/spr9qYUI3gf4bO0qqSeiEWJ5xLgPA==\n';

    const inclusionProof: TLogEntryWithInclusionProof['inclusionProof'] =
      fromPartial({
        checkpoint: { envelope: checkpoint },
        rootHash: Buffer.from(
          'WBwYpazawqUG5iErvDptvf7mpt84WIpmm+zfshgHhJs=',
          'base64'
        ),
      });

    const entry: TLogEntryWithInclusionProof = fromPartial({
      inclusionProof: inclusionProof,
      integratedTime: '1707034118',
    });

    it('does NOT throw an error', () => {
      expect(verifyCheckpoint(entry, tlogs)).toBeUndefined();
    });
  });
});
