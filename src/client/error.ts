import fetch from 'make-fetch-happen';

// Convoluted way of getting at the Response type used by make-fetch-happen
type Response = Awaited<ReturnType<typeof fetch>>;

export class HTTPError extends Error {
  public response: Response;
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
