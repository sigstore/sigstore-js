/*
Copyright 2023 The Sigstore Authors.

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
export type ImageName = {
  registry: string;
  path: string;
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

// Capture the registry domain and path components of a repository name.
const ANCHORED_NAME_RE = anchored(capture(DOMAIN_RE), '\\/', capture(NAME_RE));

// Parses a fully qualified image name into its registry and path components.
export const parseImageName = (image: string): ImageName => {
  const matches = image.match(ANCHORED_NAME_RE);
  if (!matches) {
    throw new Error(`Invalid image name: ${image}`);
  }

  return {
    registry: matches[1],
    path: matches[2],
  };
};
