/*
Copyright 2024 The Sigstore Authors.

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

export type ImageRef = {
  name: string;
  tag?: string;
  digest?: string;
};

const expression = (...res: string[]): string => res.join('');
const group = (...res: string[]): string => `(?:${expression(...res)})`;
const repeated = (...res: string[]): string => `${group(expression(...res))}+`;
const optional = (...res: string[]): string => `${group(expression(...res))}?`;
const capture = (...res: string[]): string => `(${expression(...res)})`;
const anchored = (...res: string[]): string => `^${expression(...res)}$`;

// Lower case letters, numbers
const ALPHA_NUMERIC_RE = '[a-z0-9]+';

// Separators allowed to be embedded in name components. This allows one period,
// one or two underscore or multiple dashes.
const SEPARATOR_RE = group('\\.|_|__|-+');

const TAG_RE = '[\\w][\\w.-]{0,127}';

const DIGEST_RE =
  '[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][A-Fa-f0-9]{32,}';

// Registry path component names to start with at least one letter or number,
// with following parts able to be separated by one period, one or two
// underscores or multiple dashes.
const NAME_COMPONENT_RE = expression(
  ALPHA_NUMERIC_RE,
  optional(repeated(SEPARATOR_RE, ALPHA_NUMERIC_RE))
);

const NAME_RE = expression(
  NAME_COMPONENT_RE,
  repeated(optional('\\/', NAME_COMPONENT_RE))
);

// Component of the registry domain must be at least one letter or number, with
// following parts able to be separated by a dash.
const DOMAIN_COMPONENT_RE = group(
  '[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]'
);

// Restricts the registry domain to be one or more period separated components
// followed by an optional port.
const DOMAIN_RE = expression(
  DOMAIN_COMPONENT_RE,
  optional(repeated('\\.', DOMAIN_COMPONENT_RE)),
  optional(':[0-9]+')
);

const ANCHORED_IMAGE_REF_RE = anchored(
  capture(expression(DOMAIN_RE, '\\/', NAME_RE)),
  optional('[:]' + capture(TAG_RE)),
  optional('[@]' + capture(DIGEST_RE))
);

// Parses a fully qualified image name into its registry and path components.
export const parseImageName = (image: string): ImageRef => {
  const matches = image.match(ANCHORED_IMAGE_REF_RE);

  if (!matches) {
    throw new Error(`Invalid image name: ${image}`);
  }

  return {
    name: matches[1],
    tag: matches[2],
    digest: matches[3],
  };
};
