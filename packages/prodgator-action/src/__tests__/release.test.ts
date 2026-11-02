import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
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
  it('ships only the runtime files', async () => {
    // A computed file URL keeps tsc from resolving the untyped .mjs script; vitest imports it as usual.
    const { releaseFiles } = await import(pathToFileURL(join(root, 'scripts', 'prepare-release.mjs')).href);
    const files = releaseFiles(root);
    expect(files).toEqual(expect.arrayContaining(['action.yml', 'dist/index.js', 'README.md', 'LICENSE', 'SECURITY.md']));
    for (const f of files) expect(f).toMatch(/^(action\.yml|README\.md|LICENSE|SECURITY\.md|dist\/index\.js(\.LEGAL\.txt)?)$/);
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
