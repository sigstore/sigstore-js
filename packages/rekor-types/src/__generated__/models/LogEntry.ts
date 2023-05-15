/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */

import type { InclusionProof } from './InclusionProof';

export type LogEntry = Record<string, {
    /**
     * This is the SHA256 hash of the DER-encoded public key for the log at the time the entry was included in the log
     */
    logID: string;
    logIndex: number;
    body: any;
    integratedTime: number;
    attestation?: {
        data?: any;
    };
    verification?: {
        inclusionProof?: InclusionProof;
        /**
         * Signature over the logID, logIndex, body and integratedTime.
         */
        signedEntryTimestamp?: string;
    };
}>;
