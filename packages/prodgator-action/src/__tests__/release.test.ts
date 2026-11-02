import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { pathToFileURL } from 'url';
import { parse } from 'yaml';

const root = join(__dirname, '..', '..');

describe('release metadata', () => {
  it('action.yml runs the bundled entry on node24 and documents every input main.ts reads', () => {
    const action = parse(readFileSync(join(root, 'action.yml'), 'utf8'));
    expect(action.runs).toEqual({ using: 'node24', main: 'dist/index.js' });
    const inputs = Object.keys(action.inputs);
    const main = readFileSync(join(root, 'src', 'inputs.ts'), 'utf8');
    for (const name of [...main.matchAll(/get\('([a-z-]+)'\)/g)].map((m) => m[1])) expect(inputs).toContain(name);
    expect(action.inputs['fail-on-error'].default).toBe('false');
  });
  it('the README shows the id-token permission and if: always()', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    expect(readme).toContain('id-token: write');
    expect(readme).toContain('if: always()');
  });
});

describe('action version stamp', () => {
  const load = async () => (await import(pathToFileURL(join(root, 'scripts', 'build.mjs')).href)) as { actionVersion: (env: Record<string, string | undefined>) => string };
  it('takes the release version from ACTION_VERSION, with or without the v', async () => {
    const { actionVersion } = await load();
    expect(actionVersion({ ACTION_VERSION: '1.4.1' })).toBe('1.4.1');
    expect(actionVersion({ ACTION_VERSION: 'v1.5.0' })).toBe('1.5.0');
  });
  it('builds as dev when no version is given, and refuses a malformed one', async () => {
    const { actionVersion } = await load();
    expect(actionVersion({})).toBe('dev');
    expect(() => actionVersion({ ACTION_VERSION: '1.4' })).toThrow(/1\.2\.3/);
    expect(() => actionVersion({ ACTION_VERSION: '1.4.1"; evil' })).toThrow();
  });
});

type Mirror = {
  mirrorFiles: (repoRoot: string) => { from: string; to: string }[];
  parseArgs: (argv: string[], root: string) => { out: string; sourceCommit: string; repoRoot: string };
  checkStamp: (bundle: string, version: string) => void;
  writeMirror: (o: { repoRoot: string; out: string; sourceCommit: string; distDir: string }, opts?: { requireClean?: boolean }) => { version: string };
  assertSeparateOut: (out: string, repoRoot: string) => void;
  assertCleanSource: (repoRoot: string, sourceCommit: string) => void;
};
const loadMirror = async () => (await import(pathToFileURL(join(root, 'scripts', 'mirror.mjs')).href)) as Mirror;
const repoRoot = join(root, '..', '..');
const SHA = 'a'.repeat(40);

describe('mirror script', () => {
  const temps: string[] = [];
  afterEach(() => {
    for (const t of temps.splice(0)) rmSync(t, { recursive: true, force: true });
  });
  it('lists the action package, the report core slice and the four root copies, nothing else', async () => {
    const { mirrorFiles } = await loadMirror();
    const files = mirrorFiles(repoRoot);
    const to = files.map((f) => f.to);
    for (const p of ['packages/prodgator-action/src/main.ts', 'packages/prodgator-action/package-lock.json', 'packages/prodgator-action/scripts/build.mjs', 'packages/prodgator-report/src/core/index.ts', 'packages/prodgator-report/src/core/__tests__/symlinks.ts', 'packages/prodgator-report/package.json', 'packages/prodgator-report/package-lock.json']) expect(to).toContain(p);
    for (const f of ['action.yml', 'README.md', 'LICENSE', 'SECURITY.md']) expect(files).toContainEqual({ from: `packages/prodgator-action/${f}`, to: f });
    for (const { from } of files) expect(from).toMatch(/^packages\/(prodgator-action\/|prodgator-report\/(src\/core\/|package\.json$|package-lock\.json$|LICENSE$))/);
    expect(to.some((p) => p.startsWith('packages/prodgator-action/dist'))).toBe(false);
  });
  it('mirrors only the symlinks helper from the report core tests, and no fixtures', async () => {
    const { mirrorFiles } = await loadMirror();
    const to = mirrorFiles(repoRoot).map((f) => f.to);
    expect(to.filter((p) => p.startsWith('packages/prodgator-report/src/core/__tests__/'))).toEqual(['packages/prodgator-report/src/core/__tests__/symlinks.ts']);
    expect(to.filter((p) => p.startsWith('packages/prodgator-report/src/core/') && /\.(sarif|json)$/.test(p))).toEqual([]);
  });
  it('parses arguments strictly', async () => {
    const { parseArgs } = await loadMirror();
    expect(parseArgs(['--out', '/tmp/x', '--source-commit', SHA], '/repo')).toEqual({ out: '/tmp/x', sourceCommit: SHA, repoRoot: '/repo' });
    expect(parseArgs(['--out', '/tmp/x', '--source-commit', SHA, '--repo-root', '/other'], '/repo').repoRoot).toBe('/other');
    expect(() => parseArgs(['--out', '/tmp/x', '--source-commit', 'abc123'], '/repo')).toThrow(/40/);
    expect(() => parseArgs(['--out', '/tmp/x', '--source-commit', 'A'.repeat(40)], '/repo')).toThrow(/40/);
    expect(() => parseArgs(['--out', '/tmp/x', '--source-commit', SHA, '--force', 'x'], '/repo')).toThrow(/Unknown/);
    expect(() => parseArgs(['--out'], '/repo')).toThrow(/value/);
    expect(() => parseArgs(['--out', '/tmp/x'], '/repo')).toThrow(/source-commit/);
  });
  it('accepts the stamp of the version and rejects a dev build', async () => {
    const { checkStamp } = await loadMirror();
    expect(() => checkStamp('x `prodgator-report-action/${true ? "1.5.0" : "dev"}` y', '1.5.0')).not.toThrow();
    expect(() => checkStamp('x `prodgator-report-action/${false ? "1.5.0" : "dev"}` y', '1.5.0')).toThrow(/ACTION_VERSION=1\.5\.0/);
    expect(() => checkStamp('x `prodgator-report-action/${true ? "1.4.1" : "dev"}` y', '1.5.0')).toThrow(/ACTION_VERSION/);
  });
  it('writes the tree, keeps public-repository files and removes stale ones', async () => {
    const { writeMirror } = await loadMirror();
    const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version as string;
    const tmp = mkdtempSync(join(tmpdir(), 'mirror-test-'));
    temps.push(tmp);
    const distDir = join(tmp, 'fake-dist');
    const out = join(tmp, 'out');
    mkdirSync(distDir, { recursive: true });
    writeFileSync(join(distDir, 'index.js'), `"use strict"; var ua = \`prodgator-report-action/\${true ? "${version}" : "dev"}\`;`);
    writeFileSync(join(distDir, 'index.js.LEGAL.txt'), 'legal');
    mkdirSync(join(out, '.github'), { recursive: true });
    mkdirSync(join(out, 'packages'), { recursive: true });
    mkdirSync(join(out, 'dist'), { recursive: true });
    writeFileSync(join(out, '.github', 'x'), 'keep');
    writeFileSync(join(out, '.gitignore'), 'node_modules\n');
    writeFileSync(join(out, 'packages', 'old.txt'), 'stale');
    writeFileSync(join(out, 'dist', 'old.js'), 'stale');
    writeMirror({ repoRoot, out, sourceCommit: SHA, distDir }, { requireClean: false });
    expect(readFileSync(join(out, 'VERSION'), 'utf8')).toBe(`${version}\n`);
    expect(readFileSync(join(out, 'SOURCE_COMMIT'), 'utf8')).toBe(`${SHA}\n`);
    expect(readFileSync(join(out, '.github', 'x'), 'utf8')).toBe('keep');
    expect(readFileSync(join(out, '.gitignore'), 'utf8')).toBe('node_modules\n');
    expect(existsSync(join(out, 'packages', 'old.txt'))).toBe(false);
    expect(existsSync(join(out, 'dist', 'old.js'))).toBe(false);
    expect(readFileSync(join(out, 'dist', 'index.js.LEGAL.txt'), 'utf8')).toBe('legal');
    expect(existsSync(join(out, 'dist', 'index.js'))).toBe(true);
    expect(readFileSync(join(out, 'action.yml'))).toEqual(readFileSync(join(root, 'action.yml')));
    expect(existsSync(join(out, 'packages', 'prodgator-report', 'src', 'core', 'index.ts'))).toBe(true);
  });
  it('refuses an output that is the source repository or a parent of it, allows one inside', async () => {
    const { assertSeparateOut, writeMirror } = await loadMirror();
    expect(() => assertSeparateOut('/a/repo', '/a/repo')).toThrow(/separate checkout/);
    expect(() => assertSeparateOut('/a/repo/', '/a/repo')).toThrow(/separate checkout/);
    expect(() => assertSeparateOut('/a', '/a/repo')).toThrow(/separate checkout/);
    expect(() => assertSeparateOut('/', '/a/repo')).toThrow(/separate checkout/);
    expect(() => assertSeparateOut('/a/repo/public', '/a/repo')).not.toThrow();
    expect(() => assertSeparateOut('/a/other', '/a/repo')).not.toThrow();
    expect(() => assertSeparateOut('/a/repo-public', '/a/repo')).not.toThrow();
    // The guard runs before anything is removed.
    expect(() => writeMirror({ repoRoot, out: repoRoot, sourceCommit: SHA, distDir: join(root, 'dist') }, { requireClean: false })).toThrow(/separate checkout/);
    expect(existsSync(join(root, 'package.json'))).toBe(true);
  });
  it('refuses a source tree that is not a clean checkout of the source commit', async () => {
    const { assertCleanSource } = await loadMirror();
    expect(() => assertCleanSource(repoRoot, SHA)).toThrow(/HEAD is/);
    const git = (...args: string[]) => execFileSync('git', args, { encoding: 'utf8' }).trim();
    const tmp = mkdtempSync(join(tmpdir(), 'mirror-git-'));
    temps.push(tmp);
    git('init', '-q', tmp);
    mkdirSync(join(tmp, 'packages', 'prodgator-action'), { recursive: true });
    writeFileSync(join(tmp, 'packages', 'prodgator-action', 'a.txt'), 'one');
    git('-C', tmp, 'add', '.');
    git('-C', tmp, '-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'x');
    const head = git('-C', tmp, 'rev-parse', 'HEAD');
    expect(() => assertCleanSource(tmp, head)).not.toThrow();
    writeFileSync(join(tmp, 'untracked.txt'), 'u');
    expect(() => assertCleanSource(tmp, head)).not.toThrow();
    writeFileSync(join(tmp, 'packages', 'prodgator-action', 'a.txt'), 'two');
    expect(() => assertCleanSource(tmp, head)).toThrow(/a\.txt/);
  });
});
