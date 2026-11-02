import { execFileSync } from 'child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { dirname, isAbsolute, join, relative, resolve } from 'path';
import { fileURLToPath } from 'url';

const SHA = /^[0-9a-f]{40}$/;
const SOURCE_PATHS = [
  'packages/prodgator-action',
  'packages/prodgator-report/src/core',
  'packages/prodgator-report/package.json',
  'packages/prodgator-report/package-lock.json',
  'packages/prodgator-report/LICENSE',
];
const ROOT_COPIES = ['action.yml', 'README.md', 'LICENSE', 'SECURITY.md'];
// The report client's own tests and fixtures stay private (one fixture is a real scan). The action's tests import
// only this helper from them.
const CORE_TESTS = 'packages/prodgator-report/src/core/__tests__/';
const CORE_TEST_KEPT = `${CORE_TESTS}symlinks.ts`;

/**
 * Every file the public repository mirrors from source control, except dist/*, VERSION and SOURCE_COMMIT:
 * the action package, the slice of the report client it bundles (its src/core sources, with only the symlinks.ts
 * test helper from src/core/__tests__), and root copies of its four public files.
 * Paths are relative to the repository root and to the output directory.
 */
export function mirrorFiles(repoRoot) {
  const listed = execFileSync('git', ['-C', repoRoot, 'ls-files', '-z', '--', ...SOURCE_PATHS], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const files = listed
    .split('\0')
    .filter((p) => p && (!p.startsWith(CORE_TESTS) || p === CORE_TEST_KEPT))
    .map((p) => ({ from: p, to: p }));
  for (const f of ROOT_COPIES) files.push({ from: `packages/prodgator-action/${f}`, to: f });
  return files;
}

/** Parses `--out <dir> --source-commit <sha> [--repo-root <dir>]`; an unknown flag or a missing value throws. */
export function parseArgs(argv, defaultRepoRoot) {
  const opts = { out: undefined, sourceCommit: undefined, repoRoot: defaultRepoRoot };
  const keys = { '--out': 'out', '--source-commit': 'sourceCommit', '--repo-root': 'repoRoot' };
  for (let i = 0; i < argv.length; i += 2) {
    const key = keys[argv[i]];
    if (!key) throw new Error(`Unknown argument ${JSON.stringify(argv[i])}. Usage: mirror.mjs --out <dir> --source-commit <40 hex> [--repo-root <dir>]`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${argv[i]} needs a value.`);
    opts[key] = value;
  }
  if (!opts.out) throw new Error('--out <dir> is required.');
  if (!opts.sourceCommit) throw new Error('--source-commit <40 hex> is required.');
  if (!SHA.test(opts.sourceCommit)) throw new Error('--source-commit must be 40 lowercase hex characters.');
  return { out: resolve(opts.out), sourceCommit: opts.sourceCommit, repoRoot: resolve(opts.repoRoot) };
}

/** Throws unless the bundle carries the user agent stamp for `version` (a dev build or another version fails). */
export function checkStamp(bundle, version) {
  const stamp = `prodgator-report-action/\${true ? "${version}" : "dev"}`;
  if (!bundle.includes(stamp)) throw new Error(`dist/index.js was not built for version ${version}. Build it with ACTION_VERSION=${version} npm run build (in packages/prodgator-action) first.`);
}

/** Throws when `out` is the source repository or a parent of it; an `out` inside the repository (the workflow's public/ checkout) is fine. */
export function assertSeparateOut(out, repoRoot) {
  const rel = relative(resolve(out), resolve(repoRoot));
  if (rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))) {
    throw new Error('The output directory must be a separate checkout of prodgator-action, not the source repository or a parent of it.');
  }
}

/** Throws unless the mirrored source paths are unmodified and HEAD is `sourceCommit`. */
export function assertCleanSource(repoRoot, sourceCommit) {
  const git = (args) => execFileSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8' });
  const head = git(['rev-parse', 'HEAD']).trim();
  if (head !== sourceCommit) throw new Error(`The source tree must be a clean checkout of --source-commit ${sourceCommit}, but HEAD is ${head}.`);
  const dirty = git(['status', '--porcelain', '--untracked-files=no', '--', ...SOURCE_PATHS]).trim();
  if (dirty) throw new Error(`The source tree must be a clean checkout of --source-commit ${sourceCommit}. Changed files:\n${dirty}`);
}

/** Rewrites <out>/dist and <out>/packages plus the root files; leaves <out>/.git, .github and .gitignore alone. */
export function writeMirror({ repoRoot, out, sourceCommit, distDir }, { requireClean = true } = {}) {
  assertSeparateOut(out, repoRoot);
  if (requireClean) assertCleanSource(repoRoot, sourceCommit);
  const actionDir = join(repoRoot, 'packages', 'prodgator-action');
  const version = JSON.parse(readFileSync(join(actionDir, 'package.json'), 'utf8')).version;
  const bundlePath = join(distDir, 'index.js');
  if (!existsSync(bundlePath)) throw new Error(`${bundlePath} does not exist. Build it with ACTION_VERSION=${version} npm run build (in packages/prodgator-action) first.`);
  checkStamp(readFileSync(bundlePath, 'utf8'), version);

  rmSync(join(out, 'dist'), { recursive: true, force: true });
  rmSync(join(out, 'packages'), { recursive: true, force: true });
  const files = mirrorFiles(repoRoot);
  for (const { from, to } of files) {
    mkdirSync(dirname(join(out, to)), { recursive: true });
    cpSync(join(repoRoot, from), join(out, to));
  }
  mkdirSync(join(out, 'dist'), { recursive: true });
  cpSync(bundlePath, join(out, 'dist', 'index.js'));
  const legal = join(distDir, 'index.js.LEGAL.txt');
  if (existsSync(legal)) cpSync(legal, join(out, 'dist', 'index.js.LEGAL.txt'));
  writeFileSync(join(out, 'VERSION'), `${version}\n`);
  writeFileSync(join(out, 'SOURCE_COMMIT'), `${sourceCommit}\n`);
  console.log(`Mirrored ${files.length} files, dist and VERSION ${version} at ${sourceCommit} into ${out}.`);
  return { version, files };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const defaultRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  try {
    const { out, sourceCommit, repoRoot } = parseArgs(process.argv.slice(2), defaultRoot);
    writeMirror({ repoRoot, out, sourceCommit, distDir: join(repoRoot, 'packages', 'prodgator-action', 'dist') });
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
