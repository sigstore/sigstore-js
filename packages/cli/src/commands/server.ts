import color from '@oclif/color';
import { Command, Flags, ux } from '@oclif/core';
import {
  HandlerFn,
  fulcioHandler,
  initializeCA,
  initializeCTLog,
  initializeTLog,
  rekorHandler,
} from '@sigstore/mock';
import express from 'express';

export default class Server extends Command {
  static override description = 'start mock Sigstore services';
  static override examples = ['<%= config.bin %> <%= command.id %>'];
  static override aliases = ['start'];
  static override hidden = true;

  static override flags = {
    port: Flags.integer({
      description: 'Port to listen on',
      default: 8000,
      required: false,
    }),
    strict: Flags.boolean({
      description: 'Whether or not to enforce strict request validation',
      default: true,
      required: false,
      allowNo: true,
    }),
  };

  public async run(): Promise<void> {
    const { flags } = await this.parse(Server);

    // Set-up the fake Fuclio server
    const ca = await initializeCTLog().then((ctLog) => initializeCA(ctLog));
    const { path, fn } = fulcioHandler(ca, { strict: flags['strict'] });

    // Set-up the fake Rekor server
    const tlog = await initializeTLog();
    const rekor = rekorHandler(tlog);

    // Wire up the express server
    const app = express();
    app.use(loggerMiddleware(this.log.bind(this)));
    app.use(express.json());
    app.post(path, adapt(fn));
    app.post(rekor.path, adapt(rekor.fn));

    app.listen(flags.port, () => {
      this.log(`🚀 Server ready at http://localhost:${flags.port}`);
    });

    ux.action.start('Waiting for request');
  }
}

// Translate our generic handler into an express request handler
function adapt(handler: HandlerFn): express.RequestHandler {
  return async ({ body }, res, _) => {
    const { response, statusCode, contentType } = await handler(
      JSON.stringify(body)
    );
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }
    res.status(statusCode).send(response);
  };
}

// Express middleware to log requests to the command's logger
function loggerMiddleware(
  log: (...args: any[]) => void
): express.RequestHandler {
  return (req, res, next) => {
    res.on('finish', () => {
      log(
        req.method,
        req.url,
        (res.statusCode >= 200 && res.statusCode < 300
          ? color.green
          : color.yellow)(res.statusCode),
        color.dim(`${res.getHeader('Content-Length')}b`)
      );
    });
    next();
  };
}
