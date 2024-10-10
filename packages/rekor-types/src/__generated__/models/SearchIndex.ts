/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SearchIndex = {
    email?: string;
    publicKey?: {
        format: 'pgp' | 'x509' | 'minisign' | 'ssh' | 'tuf';
        content?: string;
        url?: string;
    };
    hash?: string;
    operator?: 'and' | 'or';
};

