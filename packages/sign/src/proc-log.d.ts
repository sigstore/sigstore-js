declare module 'proc-log' {
  type Log = {
    http(...args: unknown[]): void;
  };
  export const log: Log;
}
