export const ECDSA_SIGNATURE_ALGOS: Record<string, string> = {
  '1.2.840.10045.4.3.1': 'sha224',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};

export const RSA_SIGNATURE_ALGOS: Record<string, string> = {
  '1.2.840.113549.1.1.14': 'sha224',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
};

export const SHA2_HASH_ALGOS: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
