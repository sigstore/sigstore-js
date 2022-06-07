import { Response } from 'node-fetch';

export class HTTPError extends Error {
  private response: Response;
  constructor(response: Response) {
    super(`HTTP Error: ${response.status} ${response.statusText}`);
    this.response = response;
  }
}

export const checkStatus = (response: Response): Response => {
  if (response.ok) {
    return response;
  } else {
    throw new HTTPError(response);
  }
};
