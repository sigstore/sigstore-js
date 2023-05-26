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
import { appDataPath } from '../appdata';

describe('appDataPath', () => {
  const appName = 'foobar';

  it('it includes the app name', () => {
    expect(appDataPath(appName)).toContain(appName);
  });

  // Too complicated to mock out process.platform, os.homedir, and path.join
  // for each test case. Instead, we'll just test the happy path for each
  // platform.
  describe('platform specific checks', () => {
    it('generates the correct path for the current platform', () => {
      switch (process.platform) {
        case 'darwin':
          expect(appDataPath(appName)).toMatch(
            `/Library/Application Support/${appName}`
          );
          break;
        case 'win32':
          expect(appDataPath(appName)).toMatch(
            `\\AppData\\Local\\${appName}\\Data`
          );
          break;
        default:
          expect(appDataPath(appName)).toMatch(`/.local/share/${appName}`);
      }
    });
  });
});
