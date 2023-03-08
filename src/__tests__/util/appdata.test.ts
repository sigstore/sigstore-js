import { appDataPath } from '../../util/appdata';

describe('appDataPath', () => {
  const appName = 'sigstore-js';

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
            '/Library/Application Support/sigstore-js'
          );
          break;
        case 'win32':
          expect(appDataPath(appName)).toMatch(
            '\\AppData\\Local\\sigstore-js\\Data'
          );
          break;
        default:
          expect(appDataPath(appName)).toMatch('/.local/share/sigstore-js');
      }
    });
  });
});
