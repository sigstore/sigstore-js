import fetch, { FetchInterface } from 'make-fetch-happen';
import { checkStatus } from './error';

const DEFAULT_BASE_URL = 'https://fulcio.sigstore.dev';

export interface FulcioOptions {
  baseURL?: string;
}

export interface CertificateRequest {
  oidcToken: string;
  publicKey: string;
  challenge: string;
}

/**
 * Fulcio API client.
 */
export class Fulcio {
  private fetch: FetchInterface;
  private baseUrl: string;

  constructor(options: FulcioOptions) {
    this.fetch = fetch.defaults({
      retry: { retries: 2 },
      timeout: 5000,
      headers: {
        Accept: 'application/pem-certificate-chain',
        'Content-Type': 'application/json',
      },
    });
    this.baseUrl = options.baseURL ?? DEFAULT_BASE_URL;
  }

  public async createSigningCertificate(
    request: CertificateRequest
  ): Promise<string> {
    const url = `${this.baseUrl}/api/v1/signingCert`;

    const body = {
      publicKey: { content: request.publicKey },
      signedEmailAddress: request.challenge,
    };

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${request.oidcToken}` },
      body: JSON.stringify(body),
    });
    checkStatus(response);

    const data = await response.text();
    return data;
  }
}
