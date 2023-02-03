/* eslint-disable @typescript-eslint/no-explicit-any */
class BaseError extends Error {
  cause: any | undefined;

  constructor(message: string, cause?: any) {
    super(message);
    this.name = this.constructor.name;
    this.cause = cause;
  }
}

export class VerificationError extends BaseError {}

export class ValidationError extends BaseError {}

export class InternalError extends BaseError {}

export class PolicyError extends BaseError {}
