import { execSync } from 'child_process';
import { cpSync, existsSync, mkdirSync, rmSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { actionVersion } from './build.mjs';

export function releaseFiles(root) {
  const files = ['action.yml', 'dist/index.js', 'README.md', 'LICENSE', 'SECURITY.md'];
  if (existsSync(join(root, 'dist', 'index.js.LEGAL.txt'))) files.splice(2, 0, 'dist/index.js.LEGAL.txt');
  return files;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  // A release bundle names its own version in the user agent, so the server can tell which client sent a report.
  if (actionVersion() === 'dev') throw new Error('Set ACTION_VERSION to the release version (1.2.3); scripts/release-action.ts sets it from --tag.');
  execSync('npm run build', { cwd: root, stdio: 'inherit' });
  const out = join(root, 'release');
  rmSync(out, { recursive: true, force: true });
  for (const f of releaseFiles(root)) {
    mkdirSync(dirname(join(out, f)), { recursive: true });
    cpSync(join(root, f), join(out, f));
  }
  console.log(`Release files written to ${out}.`);
  console.log('Next (manual, see docs/runbooks/prodgator-action-release.md): copy them into prodgator/prodgator-action, commit, tag vX.Y.Z, move the v1 tag, publish the release to the Marketplace.');
}
