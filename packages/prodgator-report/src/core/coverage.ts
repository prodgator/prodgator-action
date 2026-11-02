import { XMLParser } from 'fast-xml-parser';
import { displayName, readWorkspaceText } from './safe-path';
import { cleanSourcePath } from './source-path';
import type { AttestationInput, GlobFn } from './types';

export type CoverageFormat = 'cobertura' | 'lcov';
export interface CoverageTotals { format: CoverageFormat; linesCovered: number; linesTotal: number; branchesCovered: number; branchesTotal: number }

/** A coverage report that cannot be read. The message never quotes the file. */
export class CoverageError extends Error {}

export const MAX_COVERAGE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_FILES = 200;
/** Distinct executable lines (and branches) kept for de-duplication, so memory stays bounded whatever the file says. */
const MAX_TRACKED = 3_000_000;
const MAX_COUNT = 10_000_000;

const parser = new XMLParser({
  ignoreAttributes: false, attributeNamePrefix: '', processEntities: false, htmlEntities: false, parseAttributeValue: false,
  allowBooleanAttributes: true, ignoreDeclaration: true, ignorePiTags: true,
  isArray: (name) => name === 'package' || name === 'class' || name === 'line',
});

const empty = (format: CoverageFormat): CoverageTotals => ({ format, linesCovered: 0, linesTotal: 0, branchesCovered: 0, branchesTotal: 0 });
const wholeNumber = (v: unknown): number | null => {
  if (typeof v !== 'string' || !/^\d{1,9}$/.test(v.trim())) return null;
  return Number(v);
};

/** One executable line: its best hit count and its best branch result, merged across classes and records that repeat it. */
interface Seen { hits: number; bc: number; bt: number }

function track(map: Map<string, Seen>, key: string, hits: number, bc: number, bt: number): void {
  const prev = map.get(key);
  if (prev) {
    prev.hits = Math.max(prev.hits, hits);
    if (bt > prev.bt || (bt === prev.bt && bc > prev.bc)) { prev.bc = bc; prev.bt = bt; }
    return;
  }
  if (map.size >= MAX_TRACKED) throw new CoverageError('has more executable lines than the report client reads');
  map.set(key, { hits, bc, bt });
}

function sum(format: CoverageFormat, map: Map<string, Seen>): CoverageTotals {
  const t = empty(format);
  for (const s of map.values()) {
    t.linesTotal++;
    if (s.hits > 0) t.linesCovered++;
    t.branchesTotal += s.bt;
    t.branchesCovered += s.bc;
  }
  return t;
}

/**
 * Cobertura XML (coverage.py, Istanbul's `cobertura` reporter, JaCoCo and gcovr converters). Counts the `<line>`
 * elements directly under each `<class>` (the `<methods>` copies are not counted again), merging a line that
 * several classes repeat. A `condition-coverage="50% (1/2)"` on a `branch="true"` line gives its branches.
 * When a report has no line elements, the root's `lines-valid`/`lines-covered` attributes are used.
 *
 * The XML is parsed without entity expansion and a document that declares any entity is refused, so
 * nothing is read from other files or the network (a DOCTYPE with an external DTD address is ignored).
 */
export function parseCobertura(xml: string): CoverageTotals {
  if (/<!ENTITY/i.test(xml)) throw new CoverageError('declares XML entities, which are not supported');
  let doc: any;
  try { doc = parser.parse(xml); } catch { throw new CoverageError('is not valid XML'); }
  const root = doc?.coverage === '' ? {} : doc?.coverage;
  if (!root || typeof root !== 'object') throw new CoverageError('is not a Cobertura report (no <coverage> element)');
  const seen = new Map<string, Seen>();
  for (const pkg of root.packages?.package ?? []) {
    for (const cls of pkg?.classes?.class ?? []) {
      const file = typeof cls?.filename === 'string' ? cls.filename : typeof cls?.name === 'string' ? cls.name : '';
      for (const line of cls?.lines?.line ?? []) {
        const number = wholeNumber(line?.number);
        const hits = wholeNumber(line?.hits);
        if (number === null || hits === null) continue;
        let bc = 0;
        let bt = 0;
        if (String(line.branch).toLowerCase() === 'true' && typeof line['condition-coverage'] === 'string') {
          const m = /\((\d{1,6})\/(\d{1,6})\)/.exec(line['condition-coverage']);
          if (m && Number(m[1]) <= Number(m[2])) { bc = Number(m[1]); bt = Number(m[2]); }
        }
        track(seen, `${file}\0${number}`, hits, bc, bt);
      }
    }
  }
  if (seen.size) return sum('cobertura', seen);
  const total = wholeNumber(root['lines-valid']);
  const covered = wholeNumber(root['lines-covered']);
  if (total === null || covered === null || covered > total) throw new CoverageError('has no line coverage data');
  const t = { ...empty('cobertura'), linesTotal: total, linesCovered: covered };
  const bTotal = wholeNumber(root['branches-valid']);
  const bCovered = wholeNumber(root['branches-covered']);
  if (bTotal !== null && bCovered !== null && bCovered <= bTotal) { t.branchesTotal = bTotal; t.branchesCovered = bCovered; }
  return t;
}

/**
 * LCOV tracefiles (Istanbul/nyc `lcov` reporter, lcov and genhtml, gcovr, c8, Go and Rust converters). Lines come from
 * `DA:` records and branches from `BRDA:` records, merged per source file; a record with neither falls back to
 * its `LF`/`LH` and `BRF`/`BRH` summary lines. Function records are ignored.
 */
export function parseLcov(text: string): CoverageTotals {
  const lines = new Map<string, Seen>();
  // The same block seen twice (a merged tracefile) counts once.
  const branches = new Map<string, number>();
  const t = empty('lcov');
  let sf: string | null = null;
  let sawRecord = false;
  let recordHasDa = false;
  let recordHasBr = false;
  let lf: number | null = null; let lh: number | null = null; let brf: number | null = null; let brh: number | null = null;

  const flush = () => {
    if (sf === null) return;
    if (!recordHasDa && lf !== null && lh !== null && lh <= lf) { t.linesTotal += lf; t.linesCovered += lh; }
    if (!recordHasBr && brf !== null && brh !== null && brh <= brf) { t.branchesTotal += brf; t.branchesCovered += brh; }
    sf = null; recordHasDa = false; recordHasBr = false; lf = lh = brf = brh = null;
  };

  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line.startsWith('SF:')) { flush(); sf = line.slice(3); sawRecord = true; continue; }
    if (sf === null) continue;
    if (line === 'end_of_record') { flush(); continue; }
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const tag = line.slice(0, colon);
    const args = line.slice(colon + 1).split(',');
    if (tag === 'DA' && args.length >= 2) {
      const n = wholeNumber(args[0]);
      const hits = wholeNumber(args[1]);
      if (n === null || hits === null) continue;
      recordHasDa = true;
      track(lines, `${sf}\0${n}`, hits, 0, 0);
    } else if (tag === 'BRDA' && args.length === 4) {
      const n = wholeNumber(args[0]);
      const block = wholeNumber(args[1]);
      const branch = wholeNumber(args[2]);
      const taken = args[3].trim() === '-' ? 0 : wholeNumber(args[3]);
      if (n === null || block === null || branch === null || taken === null) continue;
      recordHasBr = true;
      const key = `${sf}\0${n}\0${block}\0${branch}`;
      if (!branches.has(key) && branches.size >= MAX_TRACKED) throw new CoverageError('has more branches than the report client reads');
      branches.set(key, Math.max(branches.get(key) ?? 0, taken));
    } else if (tag === 'LF') lf = wholeNumber(args[0]);
    else if (tag === 'LH') lh = wholeNumber(args[0]);
    else if (tag === 'BRF') brf = wholeNumber(args[0]);
    else if (tag === 'BRH') brh = wholeNumber(args[0]);
  }
  flush();
  if (!sawRecord) throw new CoverageError('is not an LCOV report (no SF: records)');
  const fromDa = sum('lcov', lines);
  t.linesTotal += fromDa.linesTotal; t.linesCovered += fromDa.linesCovered;
  for (const taken of branches.values()) { t.branchesTotal++; if (taken > 0) t.branchesCovered++; }
  return t;
}

/** Cobertura XML starts with `<`, LCOV never does. */
export function parseCoverage(text: string): CoverageTotals {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return body.trimStart().startsWith('<') ? parseCobertura(body) : parseLcov(body);
}

const percent = (covered: number, total: number) => Math.round((covered / total) * 10000) / 100;

/**
 * Reads every matched Cobertura or LCOV file through safe-path (workspace only, no symlinks out, no .git) and
 * sums them into one `coverage` attestation named `coverage`: `lines` and, when any file reports branches,
 * `branches`, both as percentages. Only those two numbers are sent, never file names or contents.
 *
 * It is all or nothing: if a matched file is refused, too large or not a coverage report, no attestation is sent
 * and a warning names the file, because a total over some of the files would overstate coverage.
 * The server derives the status; a policy rule supplies the threshold.
 */
export async function coverageAttestations(
  patterns: string[],
  opts: { glob: GlobFn; workspace: string; warn: (message: string) => void },
): Promise<AttestationInput[]> {
  if (!patterns.length) return [];
  const files = (await opts.glob(patterns)).slice(0, MAX_FILES);
  const total = empty('lcov');
  const paths: string[] = [];
  let problem = false;
  for (const f of files) {
    const r = await readWorkspaceText(opts.workspace, f, { maxBytes: MAX_COVERAGE_FILE_BYTES, display: displayName(opts.workspace, f) });
    if (!r.ok) { if (r.reason !== 'missing') { opts.warn(`${r.message} and was not read as coverage`); problem = true; } continue; }
    if (r.text === null) { opts.warn(`${r.file.path} is larger than ${MAX_COVERAGE_FILE_BYTES / (1024 * 1024)} MiB and was not read as coverage`); problem = true; continue; }
    try {
      const t = parseCoverage(r.text);
      total.linesCovered += t.linesCovered; total.linesTotal += t.linesTotal;
      total.branchesCovered += t.branchesCovered; total.branchesTotal += t.branchesTotal;
      paths.push(r.file.path);
    } catch (e) {
      if (!(e instanceof CoverageError)) throw e;
      opts.warn(`${r.file.path} ${e.message}`);
      problem = true;
    }
  }
  if (problem) { opts.warn('No coverage attestation was sent because not every coverage file could be read.'); return []; }
  if (!paths.length) { opts.warn(`No coverage file matched ${patterns.join(', ')}; no coverage attestation was sent.`); return []; }
  if (total.linesTotal === 0) { opts.warn('The coverage files report no executable lines; no coverage attestation was sent.'); return []; }

  const data: Record<string, unknown> = { lines: percent(total.linesCovered, total.linesTotal) };
  if (total.branchesTotal > 0) data.branches = percent(total.branchesCovered, total.branchesTotal);
  const clean = (p: string) => { const c = cleanSourcePath(opts.workspace, p); return c.ok ? c.path : null; };
  const source = patterns.length === 1 ? clean(patterns[0]) : paths.length === 1 ? clean(paths[0]) : null;
  return [{ kind: 'coverage', name: 'coverage', data, ...(source ? { sourcePath: source } : {}) }];
}
