/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type InclusionProof = {
    /**
     * The index of the entry in the transparency log
     */
    logIndex: number;
    /**
     * The hash value stored at the root of the merkle tree at the time the proof was generated
     */
    rootHash: string;
    /**
     * The size of the merkle tree at the time the inclusion proof was generated
     */
    treeSize: number;
    /**
     * A list of hashes required to compute the inclusion proof, sorted in order from leaf to root
     */
    hashes: Array<string>;
    /**
     * The checkpoint (signed tree head) that the inclusion proof is based on
     */
    checkpoint: string;
};

