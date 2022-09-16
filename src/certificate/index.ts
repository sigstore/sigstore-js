/*
Copyright 2022 The Sigstore Authors.

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
const PEM_HEADER_PREFIX = '-----BEGIN';
const PEM_FOOTER_PREFIX = '-----END';

// Given a set of PEM-encoded certificates bundled in a single string, returns
// an array of certificates.
export function splitPEM(certificate: string): string[] {
  let certs: string[] = [];
  let cert: string[] = [];

  certificate.split('\n').forEach((line) => {
    if (line.startsWith(PEM_HEADER_PREFIX)) {
      cert = [];
    }

    if (line.length > 0) {
      cert.push(line);
    }

    if (line.startsWith(PEM_FOOTER_PREFIX)) {
      certs.push(cert.join('\n'));
    }
  });

  return certs;
}
