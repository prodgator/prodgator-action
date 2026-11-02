import { XMLParser } from 'fast-xml-parser';
import { displayName, readWorkspaceText } from './safe-path';
import { cleanSourcePath } from './source-path';
import type { AttestationInput, GlobFn } from './types';

export interface JUnitTotals { passed: number; failed: number; skipped: number; errors: number; durationSeconds: number | null; failures: Array<{ suite: string | null; name: string; file?: string; message: string | null }> }

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_FILES = 500;
const MAX_NAME = 100;
const parser = new XMLParser({
  ignoreAttributes: false, attributeNamePrefix: '', processEntities: false, allowBooleanAttributes: true,
  isArray: (name) => ['testsuite', 'testcase', 'failure', 'error'].includes(name),
});
const empty = (): JUnitTotals => ({ passed: 0, failed: 0, skipped: 0, errors: 0, durationSeconds: 0, failures: [] });
const msg = (node: any): string | null => {
  const first = Array.isArray(node) ? node[0] : node;
  const m = typeof first === 'object' ? first?.message ?? first?.['#text'] : first;
  return typeof m === 'string' && m ? m.slice(0, 1000) : null;
};

function walkSuite(suite: any, t: JUnitTotals, workspace?: string) {
  for (const inner of suite?.testsuite ?? []) walkSuite(inner, t, workspace);
  for (const tc of suite?.testcase ?? []) {
    t.durationSeconds = (t.durationSeconds ?? 0) + (Number(tc.time) || 0);
    // The test file, when the runner writes one: workspace-relative only (an absolute path outside the workspace, or a ..
    // escape, is left out), and the server cleans it again.
    const cleaned = workspace !== undefined && typeof tc.file === 'string' ? cleanSourcePath(workspace, tc.file) : null;
    const failure = { suite: typeof tc.classname === 'string' ? tc.classname : suite?.name ?? null, name: String(tc.name ?? 'unnamed'), ...(cleaned?.ok ? { file: cleaned.path } : {}) };
    if (tc.failure) { t.failed++; if (t.failures.length < 50) t.failures.push({ ...failure, message: msg(tc.failure) }); }
    else if (tc.error) { t.errors++; if (t.failures.length < 50) t.failures.push({ ...failure, message: msg(tc.error) }); }
    else if ('skipped' in tc) t.skipped++;
    else t.passed++;
  }
}

export function parseJUnitXml(xml: string, workspace?: string): JUnitTotals {
  const doc = parser.parse(xml);
  const t = empty();
  const roots = doc.testsuites ? [doc.testsuites] : [];
  if (doc.testsuite) roots.push({ testsuite: doc.testsuite });
  for (const r of roots) walkSuite(r, t, workspace);
  t.durationSeconds = Math.round((t.durationSeconds ?? 0) * 1000) / 1000;
  return t;
}

const add = (total: JUnitTotals, t: JUnitTotals) => {
  total.passed += t.passed; total.failed += t.failed; total.skipped += t.skipped; total.errors += t.errors;
  total.durationSeconds = (total.durationSeconds ?? 0) + (t.durationSeconds ?? 0);
  total.failures.push(...t.failures.slice(0, 50 - total.failures.length));
};

/**
 * Failure messages from these files are sent to Prodgator, so every matched file is read through
 * safe-path: one outside the workspace, or whose real path is outside it (a symlink), is skipped with
 * a warning and the rest are still counted.
 *
 * The files are summed into one test-results attestation. Its name is `name` when given (cut to 100
 * characters), else `junit`, so a policy that names `junit` keeps working; it never depends on the
 * patterns or on how many files were read. Its sourcePath is the pattern when one pattern was given,
 * else the file when one file was read, else none; a path that cannot be vouched for is left out.
 */
export async function junitAttestations(
  patterns: string[],
  opts: { name?: string; glob: GlobFn; workspace: string; warn: (message: string) => void },
): Promise<AttestationInput[]> {
  if (!patterns.length) return [];
  const files = (await opts.glob(patterns)).slice(0, MAX_FILES);
  const total = empty();
  const paths: string[] = [];
  for (const f of files) {
    const r = await readWorkspaceText(opts.workspace, f, { maxBytes: MAX_FILE_BYTES, display: displayName(opts.workspace, f) });
    if (!r.ok) { if (r.reason !== 'missing') opts.warn(`${r.message} and was not read`); continue; }
    paths.push(r.file.path);
    add(total, r.text === null ? empty() : parseJUnitXml(r.text, opts.workspace));
  }
  // Nothing matched, or every match was refused: no attestation, as when the glob finds nothing.
  if (!paths.length) return [];

  const clean = (p: string) => { const c = cleanSourcePath(opts.workspace, p); return c.ok ? c.path : null; };
  const given = opts.name?.trim();
  const name = given ? given.slice(0, MAX_NAME) : 'junit';

  const source = patterns.length === 1 ? clean(patterns[0]) : paths.length === 1 ? clean(paths[0]) : null;
  return [{ kind: 'test-results', name, data: { ...total }, ...(source ? { sourcePath: source } : {}) }];
}
