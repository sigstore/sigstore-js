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
const BASE64_ENCODING = 'base64';
const UTF8_ENCODING = 'utf-8';

export function base64Encode(str: string): string {
  return Buffer.from(str, UTF8_ENCODING).toString(BASE64_ENCODING);
}

export function base64Decode(str: string): string {
  return Buffer.from(str, BASE64_ENCODING).toString(UTF8_ENCODING);
}
