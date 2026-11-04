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
interface Nock {
  restore(): void;
}

export function restoreNock(packagePath: string): void {
  // Resolve the Nock instance used by the package that installed the interceptor.
  const modulePath = require.resolve('nock', { paths: [packagePath] });
  const nockModule: Nock | { default: Nock } = require(modulePath);
  const nock = 'default' in nockModule ? nockModule.default : nockModule;
  nock.restore();
}
