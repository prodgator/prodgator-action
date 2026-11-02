import { createHash } from 'crypto';

export interface SarifCounts { critical: number; high: number; medium: number; low: number; suppressed: number }

/*
 * Counts a SARIF file the way the server's findings parser stores it (issue 826), so the counts on a scan attestation
 * match the open findings the same file produces on the Security page. This is a copy of the rules in
 * infra/lambda/shared/security-findings/parsers/sarif.ts (and the dedup in store/findings.ts after parseReport's sort);
 * a parity test runs both on the same documents. Change both together.
 *
 * - Results of kind pass, notApplicable and informational are skipped.
 * - A result with baselineState "absent" is fixed: not counted.
 * - A result whose suppressions are all accepted (each with no status or status accepted; any other status keeps the result actionable) is counted in `suppressed` only.
 * - Severity: security-severity on the result, else on its rule (driver or extension), else the level. Secrets with no
 *   score are high.
 * - A result counts once per finding id (rule id and fingerprint), within and across runs. Only the first 20 runs are read.
 *
 * Known gaps, both rare: the server names a result with no fingerprint by its code snippet when the blame sidecar has
 * one (this client builds that sidecar after counting), and it trims the repository name out of absolute paths that
 * contain it. Either can only split or merge results that have no fingerprint at all. Counts can also differ from stored findings past the server's findings limit per report, and by later states (carried-over dismissals, fixed): the match holds per upload.
 */

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const posInt = (v: unknown): number | null => (Number.isInteger(v) && (v as number) > 0 ? (v as number) : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

type Severity = 'critical' | 'high' | 'medium' | 'low';
const MAX_RUNS = 20;
const SKIP_KINDS = new Set(['pass', 'notApplicable', 'informational']);
const RULE_ID_MAX = 200;
const NATIVE_ID_MAX = 512;
const FINGERPRINTS_MAX = 10;
const FINGERPRINT_VALUE_MAX = 200;
const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_WORDS: Record<string, Severity> = {
  critical: 'critical', high: 'high', error: 'high', medium: 'medium', moderate: 'medium', warning: 'medium',
  low: 'low', negligible: 'low', info: 'low', informational: 'low', none: 'low', note: 'low', minor: 'low',
};
const SECRET_TOOLS = [/gitleaks/i, /trufflehog/i, /detect-secrets/i, /ggshield|gitguardian/i, /secret[- ]scanning/i, /secretlint/i, /noseyparker|nosey parker/i];

const sha256Hex = (...parts: Array<string | number | null | undefined>) =>
  createHash('sha256').update(parts.map((p) => (p === null || p === undefined ? '' : String(p))).join('\u001f')).digest('hex');

function clampText(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (!t) return null;
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function severityFromText(v: unknown): Severity | null {
  if (typeof v !== 'string') return null;
  const key = v.trim().toLowerCase();
  return Object.hasOwn(SEVERITY_WORDS, key) ? SEVERITY_WORDS[key] : null;
}

/** A score above 0 and at most 10, rounded to one decimal, else null. */
function scoreOf(v: unknown): number | null {
  const raw = typeof v === 'string' || typeof v === 'number' ? parseFloat(String(v)) : NaN;
  return Number.isFinite(raw) && raw > 0 && raw <= 10 ? Math.round(raw * 10) / 10 : null;
}

function severityFromScore(score: number | null): Severity | null {
  if (score === null || score <= 0) return null;
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
}

function normalizePath(v: unknown, repository: string | null): string | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  let p = v.trim();
  try { p = decodeURIComponent(p); } catch { /* keep as given */ }
  p = p.replace(/\\/g, '/').replace(/^file:\/\//i, '');
  const repoName = repository?.split('/')[1];
  if (p.startsWith('/') && repoName) {
    const marker = `/${repoName}/`;
    const at = p.lastIndexOf(marker);
    if (at >= 0) p = p.slice(at + marker.length);
  }
  p = p.replace(/^\/github\/workspace\//, '').replace(/^\/home\/runner\/work\/[^/]+\/[^/]+\//, '');
  p = p.replace(/^\.\//, '').replace(/^\/+/, '').replace(/\/{2,}/g, '/');
  if (!p || p.split('/').some((s) => s === '..')) return null;
  return p.slice(0, 1024);
}

function firstFingerprint(result: Obj): string | null {
  const out: Record<string, string> = {};
  for (const source of [result.partialFingerprints, result.fingerprints]) {
    if (!isObj(source)) continue;
    for (const key of Object.keys(source).sort()) {
      const value = source[key];
      if (typeof value !== 'string' || !(/(hash|fingerprint)/i.test(key) || /\/v\d+$/.test(key))) continue;
      if (Object.keys(out).length >= FINGERPRINTS_MAX) break;
      if (!(key in out)) out[key] = value.slice(0, FINGERPRINT_VALUE_MAX);
    }
  }
  return Object.hasOwn(out, 'primaryLocationLineHash') ? out.primaryLocationLineHash : Object.values(out)[0] ?? null;
}

const idMatches = (ruleId: string, descriptorId: unknown) =>
  typeof descriptorId === 'string' && (ruleId === descriptorId || ruleId.startsWith(`${descriptorId}/`));

/** The rule descriptor of a result: by index (into the driver or the extension `rule.toolComponent` names), else by id. */
function ruleFor(result: Obj, run: Obj, driverRules: unknown[], byId: Map<string, Obj>): Obj {
  const ref: Obj = isObj(result.rule) ? result.rule : {};
  const id = typeof result.ruleId === 'string' ? result.ruleId : typeof ref.id === 'string' ? ref.id : null;
  const idx = Number.isInteger(result.ruleIndex) ? result.ruleIndex : Number.isInteger(ref.index) ? ref.index : null;
  let rules: unknown[] = driverRules;
  if (isObj(ref.toolComponent)) {
    const tc = ref.toolComponent;
    const extensions = arr(run.tool?.extensions);
    const component = Number.isInteger(tc.index) ? extensions[tc.index]
      : typeof tc.name === 'string' ? (tc.name === run.tool?.driver?.name ? run.tool.driver : extensions.find((e: Obj) => isObj(e) && e.name === tc.name))
        : null;
    rules = isObj(component) ? arr(component.rules) : [];
  }
  const indexed = idx !== null && idx >= 0 && idx < rules.length && isObj(rules[idx]) ? rules[idx] as Obj : null;
  if (indexed && (!id || idMatches(id, indexed.id))) return indexed;
  if (!id) return {};
  for (let key: string = id; ; key = key.slice(0, key.lastIndexOf('/'))) {
    const hit = byId.get(key);
    if (hit) return hit;
    if (!key.includes('/')) return {};
  }
}

/** The server's first category check (sarif-category.ts step 1): a secret scanner, a SECRETS tool type or a secret tag. */
function isSecret(result: Obj, rule: Obj, run: Obj): boolean {
  const driver = isObj(run.tool?.driver) ? run.tool.driver : {};
  const props = isObj(result.properties) ? result.properties : {};
  const toolName = str(props.scanner_name) ?? str(props.scanner_details?.tool_name) ?? str(run.tool?.driver?.name);
  const nested = toolName !== str(driver.name);
  const names = [toolName, nested ? null : str(driver.fullName), nested ? null : str(driver.informationUri)];
  if (names.some((n) => !!n && SECRET_TOOLS.some((re) => re.test(n)))) return true;
  const tags = [...arr(rule.properties?.tags), ...arr(result.properties?.tags)]
    .filter((t): t is string => typeof t === 'string').map((t) => t.toLowerCase());
  const toolType = tags.map((t) => /^tool_type::(\w+)$/.exec(t)?.[1]).find(Boolean) ?? null;
  return toolType === 'secrets' || tags.includes('secret') || tags.includes('secrets');
}

/**
 * Counts SARIF results by severity as the server stores them (see the rules above). Malformed input counts as nothing
 * rather than throwing, since this is a convenience, not validation. `repository` (owner/name) only shapes the id of a
 * result with no fingerprint and an absolute path.
 */
export function sarifCounts(json: string, repository: string | null = null): SarifCounts {
  const counts: SarifCounts = { critical: 0, high: 0, medium: 0, low: 0, suppressed: 0 };
  let doc: unknown;
  try { doc = JSON.parse(json); } catch { return counts; }
  if (!isObj(doc) || !Array.isArray(doc.runs)) return counts;
  const seen: Array<{ id: string; severity: Severity; state: 'open' | 'dismissed' | 'fixed' }> = [];

  for (const run of doc.runs.filter(isObj).slice(0, MAX_RUNS)) {
    const driver = isObj(run.tool?.driver) ? run.tool.driver : {};
    const driverRules = arr(driver.rules);
    const byId = new Map<string, Obj>();
    for (const r of [...driverRules, ...arr(run.tool?.extensions).flatMap((e: Obj) => arr(e?.rules))]) {
      if (isObj(r) && typeof r.id === 'string' && !byId.has(r.id)) byId.set(r.id, r);
    }
    const artifacts = arr(run.artifacts);
    for (const result of arr(run.results)) {
      if (!isObj(result) || SKIP_KINDS.has(result.kind)) continue;
      const rule = ruleFor(result, run, driverRules, byId);
      const ruleId = clampText(result.ruleId ?? rule.id, RULE_ID_MAX);

      const score = scoreOf(result.properties?.['security-severity']) ?? scoreOf(rule.properties?.['security-severity']);
      const severity = severityFromScore(score)
        ?? (isSecret(result, rule, run) ? 'high' : severityFromText(result.level ?? rule.defaultConfiguration?.level ?? 'warning'))
        ?? 'medium';

      let fp = firstFingerprint(result);
      if (fp === null) {
        const physical = arr(result.locations).map((l: Obj) => l?.physicalLocation).find(isObj);
        const location = isObj(physical?.artifactLocation) ? physical.artifactLocation : {};
        const uri = typeof location.uri === 'string' ? location.uri
          : Number.isInteger(location.index) ? artifacts[location.index]?.location?.uri : null;
        const messageText = typeof result.message?.text === 'string' ? result.message.text : null;
        fp = sha256Hex(ruleId, normalizePath(uri, repository), posInt(physical?.region?.startLine), messageText).slice(0, 32);
      }

      const suppressions = arr(result.suppressions).filter(isObj);
      const suppressed = suppressions.length > 0 && suppressions.every((s) => s.status === undefined || s.status === 'accepted');
      const state = suppressed ? 'dismissed' : result.baselineState === 'absent' ? 'fixed' : 'open';
      seen.push({ id: `${ruleId ?? 'no-rule'}#${fp}`.slice(0, NATIVE_ID_MAX), severity, state });
    }
  }

  // The server sorts findings worst first (then by id, keeping file order otherwise) and keeps the last one per id.
  const ordered = seen.map((s, i) => ({ s, i }))
    .sort((a, b) => RANK[a.s.severity] - RANK[b.s.severity] || (a.s.id < b.s.id ? -1 : a.s.id > b.s.id ? 1 : 0) || a.i - b.i);
  const byFinding = new Map<string, (typeof seen)[number]>();
  for (const { s } of ordered) byFinding.set(s.id, s);
  for (const f of byFinding.values()) {
    if (f.state === 'open') counts[f.severity]++;
    else if (f.state === 'dismissed') counts.suppressed++;
  }
  return counts;
}
