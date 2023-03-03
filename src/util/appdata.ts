import os from 'os';
import path from 'path';

export function appDataPath(name: string): string {
  const homedir = os.homedir();
  switch (process.platform) {
    case 'darwin': {
      const appSupport = path.join(homedir, 'Library', 'Application Support');
      return path.join(appSupport, name);
    }
    case 'win32': {
      const localAppData =
        process.env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local');
      return path.join(localAppData, name, 'Data');
    }
    default: {
      const localData =
        process.env.XDG_DATA_HOME || path.join(homedir, '.local', 'share');
      return path.join(localData, name);
    }
  }
}
