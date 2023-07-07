import { fromPartial } from '@total-typescript/shoehorn';
import { VerificationError } from '../../../error';
import { verifyCheckpoint } from '../../../tlog/verify/checkpoint';
import * as sigstore from '../../../types/sigstore';
import { crypto } from '../../../util';

describe('verifyCheckpoint', () => {
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.hash(keyBytes);

  const publicKey: sigstore.PublicKey = {
    rawBytes: keyBytes,
    keyDetails: sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
  };

  const tlogInstance: sigstore.TransparencyLogInstance = {
    baseUrl: 'https://tlog.sigstore.dev',
    hashAlgorithm: sigstore.HashAlgorithm.SHA2_256,
    publicKey,
    logId: { keyId: keyID },
  };

  const tlogs = [
    tlogInstance,
    {
      ...tlogInstance,
      logId: undefined,
    },
    {
      ...tlogInstance,
      publicKey: undefined,
    },
    {
      ...tlogInstance,
      publicKey: { ...publicKey, rawBytes: undefined },
    },
  ];

  const checkpoint =
    'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n';

  const inclusionProof: sigstore.VerifiableTransparencyLogEntry['inclusionProof'] =
    fromPartial({
      checkpoint: { envelope: checkpoint },
      rootHash: Buffer.from(
        'rxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=',
        'base64'
      ),
    });

  const entry: sigstore.VerifiableTransparencyLogEntry = fromPartial({
    inclusionProof: inclusionProof,
    integratedTime: '1688058655',
  });

  describe('when the entry has a valid checkpoint', () => {
    it('does NOT throw an error', () => {
      expect(() => verifyCheckpoint(entry, tlogs)).not.toThrow();
    });
  });

  describe('when the entry has no inclusion proof', () => {
    const entryWithoutProof: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        logId: { keyId: keyID },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithoutProof, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the entry has no checkpoint', () => {
    const entryWithoutCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {},
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithoutCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the checkpoint has no separator', () => {
    const entryWithInvalidCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          checkpoint: { envelope: 'rekor.sigstore.dev - 2605736670972794746' },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the checkpoint signature is malformed', () => {
    const entryWithInvalidCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          checkpoint: {
            envelope:
              'rekor.sigstore.dev - 2605736670972794746\n\n— rekor.sigstore.dev foo\n',
          },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the checkpoint has no signature', () => {
    const entryWitInvalidCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          checkpoint: {
            envelope: 'rekor.sigstore.dev - 2605736670972794746\n\n',
          },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWitInvalidCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the checkpoint header is too short', () => {
    const entryWithInvalidCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          checkpoint: {
            envelope:
              'rekor.sigstore.dev\n\n— rekor.sigstore.dev wNI9ajBFAiEAu\n',
          },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the checkpoint origin is empty', () => {
    const entryWithInvalidCheckpoint: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          checkpoint: {
            envelope: '\nA\nB\nC\n\n— rekor.sigstore.dev wNI9ajBFAiEAu\n',
          },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithInvalidCheckpoint, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when the entry checkpoint has the wrong root hash', () => {
    const entry: sigstore.VerifiableTransparencyLogEntry = fromPartial({
      inclusionProof: { ...inclusionProof, rootHash: Buffer.from('foo') },
    });
    it('does NOT throw an error', () => {
      expect(() => verifyCheckpoint(entry, tlogs)).toThrow(VerificationError);
    });
  });

  describe('when the entry checkpoint has a bad signature', () => {
    const badSignatureCheckpoint =
      'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own\n';

    const entryWithBadCheckpointSig: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          ...inclusionProof,
          checkpoint: { envelope: badSignatureCheckpoint },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithBadCheckpointSig, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when there is no transparency log with the given key ID', () => {
    const checkpointWithBadKeyHint =
      'rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev xNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n';
    const entryWithBadLogID: sigstore.VerifiableTransparencyLogEntry =
      fromPartial({
        inclusionProof: {
          ...inclusionProof,
          checkpoint: { envelope: checkpointWithBadKeyHint },
        },
      });

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entryWithBadLogID, tlogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when key has validFor with empty start/end values', () => {
    const invalidTLogs = [
      {
        ...tlogInstance,
        publicKey: {
          ...publicKey,
          validFor: { start: undefined, end: undefined },
        },
      },
    ];

    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entry, invalidTLogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when key start time is after the entry time', () => {
    const invalidTLogs = [
      {
        ...tlogInstance,
        publicKey: {
          ...publicKey,
          validFor: { start: new Date('2099-01-01') },
        },
      },
    ];
    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entry, invalidTLogs)).toThrow(
        VerificationError
      );
    });
  });

  describe('when key is expired at the entry time', () => {
    const invalidTLogs = [
      {
        ...tlogInstance,
        publicKey: {
          ...publicKey,
          validFor: {
            start: new Date('2000-01-01'),
            end: new Date('2001-01-01'),
          },
        },
      },
    ];
    it('throws a VerificationError', () => {
      expect(() => verifyCheckpoint(entry, invalidTLogs)).toThrow(
        VerificationError
      );
    });
  });
});
