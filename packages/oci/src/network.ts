/*
Copyright 2026 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { BlockList, isIP, LookupFunction } from 'node:net';

export type NetworkOptions = {
  // Exact origins, including scheme and port. Also permits HTTP at these origins.
  readonly allowedPrivateOrigins?: readonly string[];
};

export class NetworkPolicyError extends Error {
  readonly code = 'EOCINETWORKPOLICY';

  constructor(reason: string) {
    super(`OCI network policy: ${reason}`);
    this.name = 'NetworkPolicyError';
  }
}

// Fetch wraps connection errors, preserving their code rather than their class.
export const isNetworkPolicyError = (error: unknown): boolean =>
  error instanceof NetworkPolicyError ||
  (error instanceof Error &&
    'code' in error &&
    error.code === 'EOCINETWORKPOLICY');

const nonPublic = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['168.63.129.16', 32],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  nonPublic.addSubnet(address, prefix, 'ipv4');
}
// Only currently allocated global-unicast IPv6 is eligible. Exclude special
// purpose/transition ranges as well as documentation prefixes.
const globalIPv6 = new BlockList();
globalIPv6.addSubnet('2000::', 3, 'ipv6');
nonPublic.addSubnet('2001::', 23, 'ipv6');
nonPublic.addSubnet('2001:db8::', 32, 'ipv6');
nonPublic.addSubnet('2002::', 16, 'ipv6');
nonPublic.addSubnet('3fff::', 20, 'ipv6');

const isPublicAddress = (address: string): boolean => {
  const family = isIP(address);
  if (family === 4) return !nonPublic.check(address, 'ipv4');
  if (family === 6) {
    return (
      globalIPv6.check(address, 'ipv6') && !nonPublic.check(address, 'ipv6')
    );
  }
  return false;
};

const parseURL = (value: string): URL => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new NetworkPolicyError('invalid destination URL');
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password
  ) {
    throw new NetworkPolicyError(
      'destination must be HTTP(S) without userinfo'
    );
  }
  return url;
};

const privateOrigins = (options: NetworkOptions): Set<string> =>
  new Set(
    (options.allowedPrivateOrigins || []).map((value) => {
      const url = parseURL(value);
      if (url.pathname !== '/' || url.search || url.hash) {
        throw new NetworkPolicyError(
          'private exceptions must be exact origins, not URLs with paths'
        );
      }
      return url.origin;
    })
  );

export const validateDestination = (
  value: string,
  options: NetworkOptions = {},
  previous?: string
): URL => {
  const url = parseURL(value);
  if (
    previous &&
    parseURL(previous).protocol === 'https:' &&
    url.protocol === 'http:'
  ) {
    throw new NetworkPolicyError('HTTPS downgrades are prohibited');
  }
  const allowed = privateOrigins(options).has(url.origin);
  if (url.protocol === 'http:' && !allowed) {
    throw new NetworkPolicyError('HTTP requires an explicit origin exception');
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (
    !allowed &&
    ((isIP(hostname) && !isPublicAddress(hostname)) ||
      hostname === 'localhost' ||
      hostname.endsWith('.localhost'))
  ) {
    throw new NetworkPolicyError(
      'non-public destinations require an explicit origin exception'
    );
  }
  return url;
};

export const destinationAgent = (
  url: URL,
  options: NetworkOptions
): http.Agent => {
  const allowed = privateOrigins(options).has(url.origin);
  const lookup: LookupFunction = (hostname, opts, callback) => {
    // This is the socket's lookup, not a preflight: return only the checked
    // results to net/tls.connect. Validate all answers before handing any back.
    dns.lookup(
      hostname,
      { all: true, family: opts.family },
      (err, addresses) => {
        if (err) {
          callback(err, []);
        } else if (
          !addresses.length ||
          (!allowed &&
            addresses.some(({ address }) => !isPublicAddress(address)))
        ) {
          callback(
            new NetworkPolicyError('DNS resolved to a non-public destination'),
            []
          );
        } else if (opts.all) {
          callback(null, addresses);
        } else {
          callback(null, addresses[0].address, addresses[0].family);
        }
      }
    );
  };
  // Do not share the dependency's global agent cache (which does not key on
  // lookup/policy). No socket pooling crosses requests or origin exceptions.
  const Agent = url.protocol === 'https:' ? https.Agent : http.Agent;
  return new Agent({ keepAlive: false, lookup });
};

export type ProxyOptions = {
  readonly proxy?: string | URL;
  readonly noProxy?: string | string[];
};

const proxyEnv = (name: string): string | undefined =>
  Object.entries(process.env).find(
    ([key, value]) => key.toLowerCase() === name && value
  )?.[1];

// Mirrors @npmcli/agent's proxy selection (including NO_PROXY suffix matching)
// but reads the environment per request. Returns the proxy to use, if any.
export const resolveProxy = (
  url: URL,
  options: ProxyOptions
): URL | undefined => {
  const proxy =
    options.proxy ||
    (url.protocol === 'https:'
      ? proxyEnv('https_proxy')
      : proxyEnv('https_proxy') || proxyEnv('http_proxy') || proxyEnv('proxy'));
  if (!proxy) return undefined;

  const noProxy = options.noProxy || proxyEnv('no_proxy') || [];
  const entries = (typeof noProxy === 'string' ? noProxy.split(',') : noProxy)
    // URL hostnames are lowercase; compare entries the same way.
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  const host = url.hostname.split('.').reverse();
  const excluded = entries.some((entry) => {
    const segments = entry.split('.').filter(Boolean).reverse();
    return (
      segments.length > 0 && segments.every((segment, i) => host[i] === segment)
    );
  });
  if (excluded) return undefined;

  try {
    return new URL(proxy);
  } catch {
    throw new NetworkPolicyError('invalid proxy URL');
  }
};
