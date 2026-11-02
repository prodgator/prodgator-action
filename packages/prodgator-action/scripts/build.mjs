import { build } from 'esbuild';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const SEMVER = /^\d+\.\d+\.\d+$/;

/**
 * The version the bundle reports in its user agent (`prodgator-report-action/<version>`): ACTION_VERSION when set
 * (the mirror workflow and the public repository's Verify dist set it from package.json), else `dev` for local and
 * CI builds.
 */
export function actionVersion(env = process.env) {
  const raw = env.ACTION_VERSION?.trim();
  if (!raw) return 'dev';
  const version = raw.replace(/^v/, '');
  if (!SEMVER.test(version)) throw new Error(`ACTION_VERSION must look like 1.2.3, got ${JSON.stringify(raw)}`);
  return version;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const version = actionVersion();
  await build({
    entryPoints: [join(root, 'src', 'index.ts')], outfile: join(root, 'dist', 'index.js'),
    bundle: true, platform: 'node', target: 'node20', format: 'cjs', legalComments: 'external',
    define: { ACTION_VERSION: JSON.stringify(version) },
  });
  console.log(`Built dist/index.js (action version ${version}).`);
}
