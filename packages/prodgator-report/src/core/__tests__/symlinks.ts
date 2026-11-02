import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/** Content of the runner file the tests try to leak. No message or request may contain it. */
export const SECRET = 'runner-secret-7f3a91';

/**
 * Whether this OS lets the test create a file symlink. Windows without Developer Mode or admin rights
 * cannot (EPERM); Linux CI can, so the file-symlink tests run there.
 */
export const fileLinks = (() => {
  try {
    const d = mkdtempSync(join(tmpdir(), 'probe-'));
    writeFileSync(join(d, 't'), 'x');
    symlinkSync(join(d, 't'), join(d, 'l'));
    return true;
  } catch {
    return false;
  }
})();

/** A file outside every workspace, like ~/.ssh/id_rsa or the job token file. Returns its path. */
export function runnerSecret(name = 'credentials', content = SECRET): string {
  const dir = mkdtempSync(join(tmpdir(), 'home-'));
  const file = join(dir, name);
  writeFileSync(file, content);
  return file;
}

/** A directory outside the workspace holding `files`. */
export function runnerDir(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'runner-'));
  for (const [n, c] of Object.entries(files)) writeFileSync(join(dir, n), c);
  return dir;
}

/** A directory symlink. Junctions need no privilege on Windows, so this runs everywhere. */
export function linkDir(target: string, path: string) {
  mkdirSync(join(path, '..'), { recursive: true });
  symlinkSync(target, path, 'junction');
}
