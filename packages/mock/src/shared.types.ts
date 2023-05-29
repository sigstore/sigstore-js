export type HandlerFnResult = {
  statusCode: number;
  response: string;
  contentType?: string;
};
export type HandlerFn = (request: string) => Promise<HandlerFnResult>;

export type Handler = {
  path: string;
  fn: HandlerFn;
};
