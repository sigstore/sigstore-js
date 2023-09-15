import color from '@oclif/color';
import { Command, Flags, ux } from '@oclif/core';
import {
  HandlerFn,
  fulcioHandler,
  initializeCA,
  initializeCTLog,
  initializeTLog,
  initializeTSA,
  rekorHandler,
  tsaHandler,
} from '@sigstore/mock';
import {
  CertificateAuthority,
  HashAlgorithm,
  PublicKeyDetails,
  TransparencyLogInstance,
  TrustedRoot,
} from '@sigstore/protobuf-specs';
import { initializeTUFRepo, tufHandlers } from '@tufjs/repo-mock';
import crypto, { generateKeyPairSync } from 'crypto';
import express from 'express';
import fs from 'fs';

const VALID_FOR_START = new Date('2023-01-01');

// TODO: Export these types from @sigstore/mock
type CA = Awaited<ReturnType<typeof initializeCA>>;
type TLog = Awaited<ReturnType<typeof initializeTLog>>;
type CTLog = Awaited<ReturnType<typeof initializeCTLog>>;
type TSA = Awaited<ReturnType<typeof initializeTSA>>;

export default class Server extends Command {
  static override description = 'start mock services';

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
    'private-key': Flags.file({
      description: 'Path to private key file (PEM format) to use for signing',
      required: false,
    }),
    'ca-clock': Flags.string({
      description: 'Static time to use for CA timestamps',
      required: false,
    }),
    'ctlog-clock': Flags.string({
      description: 'Static time to use for ctlog timestamps',
      required: false,
    }),
    'tlog-clock': Flags.string({
      description: 'Static time to use for tlog timestamps',
      required: false,
    }),
    'tsa-clock': Flags.string({
      description: 'Static time to use for TSA timestamps',
      required: false,
    }),
  };

  public async run(): Promise<void> {
    const { flags } = await this.parse(Server);
    const url = `http://localhost:${flags.port}`;

    // If a private key is provided, use it. Otherwise, generate a new one.
    let keyPair: crypto.KeyPairKeyObjectResult | undefined;
    if (flags['private-key']) {
      const keyFile = fs.readFileSync(flags['private-key']);
      keyPair = {
        privateKey: crypto.createPrivateKey(keyFile),
        publicKey: crypto.createPublicKey(keyFile),
      };
    } else {
      keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    }

    // Set-up the fake Fuclio server
    const ctlogClock = flags['ctlog-clock']
      ? new Date(flags['ctlog-clock'])
      : undefined;
    const caClock = flags['ca-clock'] ? new Date(flags['ca-clock']) : undefined;
    const ctlog = await initializeCTLog(keyPair, ctlogClock);
    const ca = await initializeCA(keyPair, ctlog, caClock);
    const fulcio = fulcioHandler(ca, {
      strict: flags['strict'],
      subjectClaim: 'sub',
    });

    // Set-up the fake Rekor server
    const tlogClock = flags['tlog-clock']
      ? new Date(flags['tlog-clock'])
      : undefined;
    const tlog = await initializeTLog(url, keyPair, tlogClock);
    const rekor = rekorHandler(tlog, { strict: flags['strict'] });

    // Set-up the fake TSA server
    const tsaClock = flags['tsa-clock']
      ? new Date(flags['tsa-clock'])
      : undefined;
    const tsa = await initializeTSA(keyPair, tsaClock);
    const timestamp = tsaHandler(tsa, { strict: flags['strict'] });

    // Build the trusted root from the key material of the fake services
    const trustedRoot = assembleTrustedRoot({ ca, tlog, ctlog, tsa, url });

    // Set-up the fake TUF server
    const tufRepo = initializeTUFRepo([
      {
        name: 'trusted_root.json',
        content: JSON.stringify(TrustedRoot.toJSON(trustedRoot)),
      },
    ]);
    const tufEndpoints = tufHandlers(tufRepo, { metadataPathPrefix: '' });

    // Wire up the express server
    const app = express();
    app.use(loggerMiddleware(this.log.bind(this)));
    app.use(express.json());
    app.post(fulcio.path, adapt(fulcio.fn));
    app.post(rekor.path, adapt(rekor.fn));
    app.post(timestamp.path, adapt(timestamp.fn));

    tufEndpoints.forEach(({ path, fn }) => {
      app.get(
        path,
        adapt(() => Promise.resolve(fn()))
      );
    });

    app.listen(flags.port, () => {
      this.log(`🚀 Server ready at ${url}`);
    });

    ux.action.start('Waiting for request');
  }
}

// Collect key material from the various services and return a populated
// TrustedRoot.
function assembleTrustedRoot({
  ca,
  tlog,
  ctlog,
  tsa,
  url,
}: {
  ca: CA;
  tlog: TLog;
  ctlog: CTLog;
  tsa: TSA;
  url: string;
}): TrustedRoot {
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    certificateAuthorities: [certificateAuthority(ca.rootCertificate, url)],
    ctlogs: [transparencyLogInstance(ctlog.publicKey, url)],
    tlogs: [transparencyLogInstance(tlog.publicKey, url)],
    timestampAuthorities: [certificateAuthority(tsa.rootCertificate, url)],
  };
}

function certificateAuthority(
  certificate: Buffer,
  url: string
): CertificateAuthority {
  return {
    subject: {
      commonName: 'sigstore',
      organization: 'sigstore.mock',
    },
    uri: url,
    certChain: {
      certificates: [{ rawBytes: certificate }],
    },
    validFor: { start: VALID_FOR_START },
  };
}

function transparencyLogInstance(
  key: Buffer,
  url: string
): TransparencyLogInstance {
  return {
    baseUrl: url,
    logId: {
      keyId: crypto.createHash('sha256').update(key).digest(),
    },
    hashAlgorithm: HashAlgorithm.SHA2_256,
    publicKey: {
      rawBytes: key,
      keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      validFor: { start: VALID_FOR_START },
    },
  };
}

// Translate our generic handler into an express request handler
function adapt(handler: HandlerFn): express.RequestHandler {
  return async ({ body }, res) => {
    const { response, statusCode, contentType } = await handler(
      JSON.stringify(body)
    );
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }
    res.status(statusCode).send(response);
  };
}

type Logger = Command['log'];

// Express middleware to log requests to the command's logger
function loggerMiddleware(log: Logger): express.RequestHandler {
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
