/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type InactiveShardLogInfo = {
    /**
     * The current hash value stored at the root of the merkle tree
     */
    rootHash: string;
    /**
     * The current number of nodes in the merkle tree
     */
    treeSize: number;
    /**
     * The current signed tree head
     */
    signedTreeHead: string;
    /**
     * The current treeID
     */
    treeID: string;
};

