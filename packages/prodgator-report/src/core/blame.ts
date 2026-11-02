import { execFile } from 'child_process';
import { createHash } from 'crypto';
import { accessSync, constants as fsConstants, realpathSync, statSync } from 'fs';
import { isAbsolute, posix as posixPath, relative, resolve, sep, win32 as win32Path } from 'path';
import { fileURLToPath } from 'url';

/**
 * Blame sidecar (Plan 18 Task 18, decision 8): for each code finding in a SARIF file, the commit that
 * introduced its lines (`git blame -w -M -C`, so reformats and moves are skipped) and a hash of the
 * normalized snippet. The server reads it next to the SARIF (`data.blame` on the scan attestation).
 *
 * Blame never fails a report (ruling C23): every error or limit is a `skipped` result with a reason,
 * and only an unreadable SARIF or a workspace that is not a git repository gives no sidecar at all.
 * Git runs through execFile with argument arrays (never a shell), paths always follow `--`, and a
 * path that resolves outside the workspace is never passed to git. File contents are never logged.
 */

export type BlameReason = 'dependency' | 'no_location' | 'missing' | 'shallow' | 'limit' | 'binary' | 'error';
export interface BlameResult {
  run: number; result: number;
  status: 'found' | 'not_applicable' | 'skipped';
  reason?: BlameReason;
  /** Introducing commit, full SHA. */
  commit?: string;
  /**
   * sha256 of the normalized lines, first 32 hex characters, read from the file at HEAD for every located code result
   * whatever its status (within the snippet allowance), so the server's finding id does not depend on blame.
   */
  snippetHash?: string;
}
export interface BlameSidecar {
  format: 'prodgator-blame';
  version: 1;
  /** sha256 of the SARIF file it describes; the server ignores a sidecar that does not match. */
  sarifSha256: string;
  head: string;
  results: BlameResult[];
  stats: { blamed: number; skipped: number; ms: number };
}

export interface GitRunner { run(args: string[], options: { cwd: string; timeoutMs: number }): Promise<string> }
export interface BlameLimits { maxResults?: number; maxMs?: number; maxDeepen?: number; maxSnippets?: number; maxSnippetMs?: number }
/**
 * What is left of one report step's blame allowance. The limits cover the whole step, not each SARIF
 * file: 60 s, 500 blamed results and 3 deepen fetches in all. gitMissing is set when git is not installed.
 * Snippet hashes have their own allowance (5000 results and 30 s per step), apart from blame, so a
 * result gets the same hash, and so the same finding id, whatever blame made of it. Their 30 s start
 * when the step first hashes (after blame), so time blame used never leaves hashing without any.
 */
export interface BlameBudget {
  deadline: number; resultsLeft: number; deepensLeft: number; gitMissing: boolean;
  /** Set when the step first hashes snippets: then plus snippetMs. */
  snippetDeadline: number | null; snippetMs: number; snippetsLeft: number;
}
export function createBlameBudget(limits: BlameLimits = {}, now = Date.now()): BlameBudget {
  return {
    deadline: now + (limits.maxMs ?? 60_000), resultsLeft: limits.maxResults ?? 500, deepensLeft: limits.maxDeepen ?? 3, gitMissing: false,
    snippetDeadline: null, snippetMs: limits.maxSnippetMs ?? 30_000, snippetsLeft: limits.maxSnippets ?? 5_000,
  };
}
export interface BlameOptions extends BlameLimits { cwd: string; git?: GitRunner; budget?: BlameBudget }

export const BLAME_SIDECAR_SUFFIX = '.prodgator-blame.json';
const MAX_RANGE_LINES = 50;
const DEEPEN_BY = 200;
/** One git call never waits longer than this, even when the overall budget has more room. */
const MAX_CALL_MS = 30_000;
/** The server reads at most 20 runs of a SARIF file (`MAX_RUNS` in infra/lambda/shared/security-findings/parsers/sarif.ts). */
const MAX_RUNS = 20;
/** Result kinds the server never turns into findings (`SKIP_KINDS` in the same file). */
const SKIP_KINDS = new Set(['pass', 'notApplicable', 'informational']);

class GitError extends Error { constructor(message: string, readonly stderr: string, readonly code?: unknown) { super(message); } }

export interface GitLookup {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** True for an executable regular file (tests replace it). */
  isExecutable?: (path: string) => boolean;
  /** The real path of a directory, or the path itself when it cannot be resolved (tests replace it). */
  realpath?: (path: string) => string;
}

const defaultIsExecutable = (platform: NodeJS.Platform) => (file: string): boolean => {
  try {
    if (!statSync(file).isFile()) return false;
    if (platform !== 'win32') accessSync(file, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
};
const defaultRealpath = (p: string): string => {
  try { return realpathSync.native(p); } catch { return p; }
};

interface GitSearch {
  /** The absolute path of git, or null. */
  git: string | null;
  /** The PATH entries git may use: the ones the search did not skip, joined again. */
  path: string;
  /** The environment name PATH was read from (`Path` on some Windows hosts). */
  pathKey: string;
}

/**
 * Searches PATH for git. The checkout is attacker-influenced: on Windows a child process looks in its working directory
 * before PATH, so a git.exe committed at the workspace root would run if git were started by name. Empty, `.` and
 * relative PATH entries are skipped, and so is any directory inside the workspace (also after following symlinks). On
 * Windows only git.exe and git.com are taken (in PATHEXT order), never a script.
 */
function searchGit(workspace: string, o: GitLookup): GitSearch {
  const platform = o.platform ?? process.platform;
  const win = platform === 'win32';
  const p = win ? win32Path : posixPath;
  const env = o.env ?? process.env;
  const isExecutable = o.isExecutable ?? defaultIsExecutable(platform);
  const realpath = o.realpath ?? defaultRealpath;
  // Windows environment names are case-insensitive (Path, PATH).
  const pathKey = (win ? Object.keys(env).find((k) => k.toUpperCase() === 'PATH') : undefined) ?? 'PATH';
  const pathValue = env[pathKey];
  const pathExt = win ? Object.entries(env).find(([k]) => k.toUpperCase() === 'PATHEXT')?.[1] : undefined;
  const exts = win
    ? [...new Set((pathExt ?? '.COM;.EXE').split(';').map((e) => e.trim().toLowerCase()).filter((e) => e === '.exe' || e === '.com'))]
    : [''];
  if (win && !exts.length) exts.push('.exe');
  const roots = [...new Set([p.resolve(workspace), p.resolve(realpath(workspace))])];
  // Inside unless the relative path climbs out (`..` as a whole segment) or is on another drive; `..hidden` is inside.
  const inside = (dir: string) => roots.some((root) => {
    const rel = p.relative(root, dir);
    return !(rel === '..' || rel.startsWith(`..${p.sep}`) || p.isAbsolute(rel));
  });
  // Absolute only: on Windows a drive letter or a UNC path (a bare `\dir` is relative to the current drive).
  const absolute = (dir: string) => (win ? /^([A-Za-z]:[\\/]|\\\\[^\\])/.test(dir) : dir.startsWith('/'));
  const kept: string[] = [];
  let git: string | null = null;
  for (const raw of (pathValue ?? '').split(win ? ';' : ':')) {
    const dir = win ? raw.trim().replace(/^"(.*)"$/, '$1') : raw;
    if (!dir || dir === '.' || !absolute(dir)) continue;
    const resolved = p.resolve(dir);
    if (inside(resolved) || inside(p.resolve(realpath(resolved)))) continue;
    kept.push(raw);
    for (const ext of git ? [] : exts) {
      const candidate = p.join(resolved, `git${ext}`);
      if (isExecutable(candidate)) { git = candidate; break; }
    }
  }
  return { git, path: kept.join(win ? ';' : ':'), pathKey };
}

/** The absolute path of git on PATH (see searchGit), or null when there is none. */
export function findGit(workspace: string, o: GitLookup = {}): string | null {
  return searchGit(workspace, o).git;
}

/**
 * The environment git runs with: PATH holds only the entries the search kept, so git's own child processes (hooks are
 * off, but helpers and pagers are looked up on PATH) never start a program from the checkout either.
 */
export function gitEnv(workspace: string, o: GitLookup = {}): NodeJS.ProcessEnv {
  const search = searchGit(workspace, o);
  const env: NodeJS.ProcessEnv = { ...(o.env ?? process.env) };
  for (const k of Object.keys(env)) if (k.toUpperCase() === 'PATH') delete env[k];
  env[search.pathKey] = search.path;
  return env;
}

/** Runs git by the absolute path findGit gives for the workspace (looked up once per workspace). */
export function gitRunnerFor(lookup: GitLookup = {}, spawn: typeof execFile = execFile): GitRunner {
  const found = new Map<string, { git: string | null; env: NodeJS.ProcessEnv }>();
  return {
    run: (args, { cwd, timeoutMs }) => new Promise((resolveRun, reject) => {
      if (!found.has(cwd)) found.set(cwd, { git: findGit(cwd, lookup), env: gitEnv(cwd, lookup) });
      const { git, env: baseEnv } = found.get(cwd)!;
      // Treated as git not being installed.
      if (!git) { reject(new GitError('git not found', '', 'ENOENT')); return; }
      spawn(git, args, {
        cwd, timeout: Math.max(1, timeoutMs), maxBuffer: 16 * 1024 * 1024, windowsHide: true, encoding: 'utf8',
        // English messages (for missing-path detection) and never a credential prompt.
        env: { ...baseEnv, LC_ALL: 'C', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
      }, (err, stdout, stderr) => {
        if (err) reject(new GitError('git failed', String(stderr ?? ''), (err as { code?: unknown }).code));
        else resolveRun(String(stdout));
      });
    }),
  };
}

export const execGit: GitRunner = gitRunnerFor();

/** Trim each line, collapse inner whitespace, drop empty lines, join with `\n`. */
export function normalizeSnippet(lines: string[]): string {
  return lines.map((l) => l.trim().replace(/\s+/g, ' ')).filter(Boolean).join('\n');
}

/** sha256 of the normalized lines, first 32 hex characters; none for lines that are all blank. */
export function snippetHashOf(lines: string[]): string | undefined {
  const snippet = normalizeSnippet(lines);
  return snippet ? createHash('sha256').update(snippet).digest('hex').slice(0, 32) : undefined;
}

// ---------------------------------------------------------------------------------------------
// Dependency findings. A minimal copy of the dependency signals in the server's categorizer,
// infra/lambda/shared/security-findings/parsers/sarif-category.ts (`categorizeSarifResult`); keep
// the two in step. Secrets and code categories win first, as they do there.
// ---------------------------------------------------------------------------------------------
type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

const SCA_TOOLS = [
  /\bgrype\b|anchore\/grype/i, /osv-scanner|google\/osv-scanner/i, /dependency-check|dependencycheck/i, /snyk open source|snyk-open-source/i,
  /\bnpm[- ]audit\b/i, /\byarn[- ]audit\b/i, /\bpnpm[- ]audit\b/i, /\bpip[- ]audit\b/i, /\bcargo[- ]audit\b/i, /\bbundler[- ]audit\b/i, /\bgovulncheck\b/i,
];
const SECRET_TOOLS = [/gitleaks/i, /trufflehog/i, /detect-secrets/i, /ggshield|gitguardian/i, /secret[- ]scanning/i, /secretlint/i, /noseyparker|nosey parker/i];
const MANIFESTS = [
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|package\.json)$/i,
  /(^|\/)(go\.sum|go\.mod)$/i,
  /(^|\/)(Gemfile\.lock|Gemfile|gems\.locked)$/i,
  /(^|\/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|Pipfile|pdm\.lock|uv\.lock|pyproject\.toml|setup\.py)$/i,
  /(^|\/)(pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|[^/]+\.jar)$/i,
  /(^|\/)(Cargo\.lock|Cargo\.toml)$/i,
  /(^|\/)(packages\.lock\.json|packages\.config|[^/]+\.csproj|[^/]+\.fsproj|[^/]+\.vbproj|[^/]+\.deps\.json)$/i,
  /(^|\/)(composer\.lock|composer\.json)$/i,
  /(^|\/)pubspec\.lock$/i, /(^|\/)Package\.resolved$/i, /(^|\/)mix\.lock$/i,
  // OS package databases inside an image.
  /(^|\/)lib\/apk\/db\/installed$/i, /(^|\/)var\/lib\/dpkg\/status(\.d\/[^/]+)?$/i, /(^|\/)var\/lib\/rpm\/(Packages|rpmdb\.sqlite|Packages\.db)$/i,
];
const isManifest = (path: string | null) => !!path && MANIFESTS.some((re) => re.test(path));

const CVE = /^CVE-\d{4}-\d{4,}$/;
const GHSA = /^GHSA(-[23456789CFGHJMPQRVWX]{4}){3}$/;
const ADVISORY_PREFIX = /^(RUSTSEC|GO|PYSEC|OSV|GSD|MAL|SNYK|RUBYSEC|DLA|DSA|USN|ALSA|RHSA|ELSA|ALAS\d*|BIT|CGA|MGASA|OESA|OPENSUSE|SUSE)-/;
const LEADING_VULN_ID = /^(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})-([^-].*)$/i;
const CHECKOV_SCA_ID = /^([A-Z]+-[A-Z0-9-]+?)_(.+)@([^@]+)$/i;
/** `normalizeVulnId` in the server's normalize.ts. */
function normalizeVulnId(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const id = v.trim().toUpperCase();
  if (!id || id.length > 64 || !/^[A-Z0-9._:-]+$/.test(id)) return null;
  if (id.startsWith('CVE-') && !CVE.test(id)) return null;
  if (id.startsWith('GHSA-') && !GHSA.test(id)) return null;
  return id;
}
const isAdvisoryId = (id: string | null): id is string => !!id && (CVE.test(id) || GHSA.test(id) || ADVISORY_PREFIX.test(id));
/** `vulnFromRuleId`: a whole advisory id, `{vuln}-{package}` (Grype) or `{vuln}_{package}@{version}` (Checkov). */
function vulnFromRuleId(ruleId: string | null): { id: string | null; rest: string | null; pkgVersion: string | null } {
  if (!ruleId) return { id: null, rest: null, pkgVersion: null };
  const whole = normalizeVulnId(ruleId);
  if (isAdvisoryId(whole)) return { id: whole, rest: null, pkgVersion: null };
  const lead = LEADING_VULN_ID.exec(ruleId);
  if (lead) return { id: normalizeVulnId(lead[1]), rest: lead[2], pkgVersion: null };
  const ck = CHECKOV_SCA_ID.exec(ruleId);
  const ckId = ck ? normalizeVulnId(ck[1]) : null;
  if (ck && isAdvisoryId(ckId)) return { id: ckId, rest: ck[2], pkgVersion: ck[3] };
  return { id: null, rest: null, pkgVersion: null };
}

const canon = (k: string) => k.toLowerCase().replace(/[-_ ]/g, '');
const prop = (bag: unknown, names: readonly string[]): unknown => {
  if (!isObj(bag)) return undefined;
  for (const key of Object.keys(bag)) if (names.includes(canon(key))) return bag[key];
  return undefined;
};
const firstStr = (v: unknown): string | null => (Array.isArray(v) ? v.map(str).find(Boolean) ?? null : str(v));
const nameValue = (v: unknown): string | null => {
  if (isObj(v)) return str(v.name);
  const s = firstStr(v);
  return s && s.length <= 300 && !/\s/.test(s) ? s : null;
};
const concreteVersion = (v: string | null): string | null => (v && v.length <= 100 && /^[A-Za-z0-9][A-Za-z0-9._+:~-]*$/.test(v) ? v : null);
/** `parsePurl` in the server's purl.ts, reduced to what the dependency check needs. */
function parsePurl(purl: unknown): { version: string | null } | null {
  if (typeof purl !== 'string' || purl.length > 2048 || !purl.startsWith('pkg:')) return null;
  const withoutSub = purl.slice(4).split('#')[0].split('?')[0];
  const at = withoutSub.lastIndexOf('@');
  const parts = (at > 0 ? withoutSub.slice(0, at) : withoutSub).split('/').filter(Boolean);
  if (parts.length < 2 || !/^[a-z][a-z0-9.+-]*$/.test(parts[0].toLowerCase()) || !parts[parts.length - 1]) return null;
  let version: string | null = null;
  if (at > 0) {
    const raw = withoutSub.slice(at + 1);
    try { version = decodeURIComponent(raw) || null; } catch { version = raw || null; }
  }
  return { version };
}
const PROP = {
  purl: ['purl', 'purls', 'packageurl', 'packageurls'],
  name: ['packagename', 'pkgname', 'package', 'componentname', 'dependency', 'dependencyname', 'artifactname', 'libraryname'],
  version: ['packageversion', 'pkgversion', 'installedversion', 'componentversion', 'dependencyversion', 'currentversion', 'version'],
  fixed: ['fixedversion', 'fixedversions', 'fixversion', 'fixversions', 'patchedversion', 'patchedversions', 'fixedin'],
} as const;
interface PkgParts { purl: string | null; name: string | null; version: string | null; fixedVersion: string | null }
/** `fromProperties`: package data in a result's or rule's properties. */
function fromProperties(bag: unknown): PkgParts | null {
  if (!isObj(bag)) return null;
  const purlText = firstStr(prop(bag, PROP.purl));
  const parsed = parsePurl(purlText);
  const pkgObj = isObj(prop(bag, ['package'])) ? prop(bag, ['package']) as Obj : null;
  // The server takes the name from the purl when no property names it; only its presence matters here.
  const name = nameValue(prop(bag, PROP.name)) ?? (parsed ? 'purl' : null);
  // A bare `version` property is only package data next to a package name or purl.
  const versionRaw = firstStr(prop(bag, PROP.version.filter((n) => n !== 'version'))) ?? (name ? firstStr(prop(bag, ['version'])) : null) ?? str(pkgObj?.version);
  const fixed = firstStr(prop(bag, PROP.fixed));
  if (!parsed && !name && !versionRaw && !fixed) return null;
  return { purl: parsed ? purlText : null, name, version: concreteVersion(versionRaw) ?? parsed?.version ?? null, fixedVersion: fixed };
}
function mergeParts(parts: Array<PkgParts | null>): PkgParts {
  const out: PkgParts = { purl: null, name: null, version: null, fixedVersion: null };
  for (const p of parts) {
    if (!p) continue;
    for (const k of Object.keys(out) as Array<keyof PkgParts>) if (!out[k] && p[k]) out[k] = p[k];
  }
  return out;
}
const PACKAGE_MESSAGES = [/^Package: *(\S+)\s*$/m, /^Package '([^']+)@([^'@]+)' is vulnerable to '/, /vulnerability in ([\w.-]+) package: ([^,\s]+), version ([^\s,]+) was found/];
const SNYK_DESCRIPTION = /^\(([^)]*)\)\s+(\S+)@(\S+)$/;

/**
 * True when the server would file this result as a dependency finding
 * (`categorizeSarifResult(...).kind === 'dependency'`), or the result sits on line 1 of a manifest.
 * `path` is the location as the server normalizes it, also for a location outside the workspace.
 */
export function isDependencyResult(result: Obj, rule: Obj, run: Obj, path: string | null, line: number | null): boolean {
  if (isManifest(path) && line === 1) return true;
  const driver = isObj(run.tool?.driver) ? run.tool.driver : {};
  const props = isObj(result.properties) ? result.properties : {};
  const toolName = str(props.scanner_name) ?? str(props.scanner_details?.tool_name) ?? str(driver.name);
  const nested = toolName !== str(driver.name);
  const toolNames = [toolName, nested ? null : str(driver.fullName), nested ? null : str(driver.informationUri)].filter((n): n is string => !!n);
  const tags = [...arr(rule.properties?.tags), ...arr(result.properties?.tags)].filter((t): t is string => typeof t === 'string').map((t) => t.toLowerCase());
  const toolType = tags.map((t) => /^tool_type::(\w+)$/.exec(t)?.[1]).find(Boolean) ?? null;

  // 1 and 2: secrets and explicit code categories win.
  if (toolNames.some((n) => SECRET_TOOLS.some((re) => re.test(n))) || toolType === 'secrets' || tags.includes('secret') || tags.includes('secrets')) return false;
  if (toolType === 'sast' || toolType === 'iac' || tags.includes('misconfiguration')) return false;

  // 3: dependency evidence, in the server's order.
  if (toolNames.some((n) => SCA_TOOLS.some((re) => re.test(n))) || toolType === 'sca' || toolType === 'container') return true;
  const parts = mergeParts([fromProperties(result.properties), fromProperties(rule.properties)]);
  const explicitName = [result.properties, rule.properties].some((b) => !!nameValue(prop(b, ['packagename', 'pkgname'])));
  if (parts.purl || explicitName || (parts.name && (parts.version || parts.fixedVersion))) return true;
  const message = typeof result.message?.text === 'string' ? result.message.text : '';
  if (PACKAGE_MESSAGES.some((re) => re.test(message))) return true;

  const ruleVuln = vulnFromRuleId(str(result.ruleId) ?? str(rule.id));
  const snyk = SNYK_DESCRIPTION.exec(str(rule.fullDescription?.text) ?? '');
  const vulnIds = [
    ruleVuln.id,
    ...[...arr(rule.deprecatedIds), ...arr(rule.properties?.aliases)].map(normalizeVulnId).filter(isAdvisoryId),
    ...(snyk ? snyk[1].split(/[,\s]+/).map(normalizeVulnId).filter(isAdvisoryId) : []),
  ].filter(Boolean);
  if (!vulnIds.length) return false;
  if (ruleVuln.rest && ruleVuln.pkgVersion) return true;
  if (isManifest(path) || str(run.properties?.imageName)) return true;
  return tags.some((t) => ['vulnerability', 'dependency', 'dependencies', 'sca', 'supply-chain', 'security'].includes(t));
}

/**
 * True when the server names the result by a SARIF fingerprint (`fingerprintsOf` in the server's parsers/sarif.ts: a
 * string under a key naming a hash or fingerprint, or a versioned key, in `partialFingerprints` or `fingerprints`).
 */
function hasFingerprints(result: Obj): boolean {
  return [result.partialFingerprints, result.fingerprints].some((source) => isObj(source)
    && Object.entries(source).some(([key, value]) => typeof value === 'string' && (/(hash|fingerprint)/i.test(key) || /\/v\d+$/.test(key))));
}

/** Each run's rules by id (the first rule with an id wins), built once per run so a large SARIF is not searched per result. */
const rulesById = new WeakMap<Obj, Map<unknown, Obj>>();
/** The rule id the server reads (the result's `ruleId`, else its rule's id). */
const hasRuleId = (result: Obj, run: Obj) => !!(str(result.ruleId) ?? str(ruleFor(result, run).id));

function ruleFor(result: Obj, run: Obj): Obj {
  const driverRules = arr(run.tool?.driver?.rules);
  const ref: Obj = isObj(result.rule) ? result.rule : {};
  const idx = Number.isInteger(result.ruleIndex) ? result.ruleIndex : Number.isInteger(ref.index) ? ref.index : null;
  if (idx !== null && !isObj(ref.toolComponent) && isObj(driverRules[idx])) return driverRules[idx];
  const id = str(result.ruleId) ?? str(ref.id);
  let byId = rulesById.get(run);
  if (!byId) {
    byId = new Map();
    for (const r of [...driverRules, ...arr(run.tool?.extensions).flatMap((e: Obj) => arr(e?.rules))]) {
      if (isObj(r) && !byId.has(r.id)) byId.set(r.id, r);
    }
    rulesById.set(run, byId);
  }
  return byId.get(id) ?? {};
}

// ---------------------------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------------------------
interface Located {
  /** `ok`: a file in the workspace and a line range; `outside`: a file git must not read; `none`: no file or no line. */
  kind: 'ok' | 'outside' | 'none';
  /** Workspace-relative path with forward slashes (only for `ok`). */
  path: string | null;
  /** The location as the server normalizes it, for the dependency check (also for `outside` and `none`). */
  categoryPath: string | null;
  start: number | null;
  end: number;
}

function uriToPath(uri: string): string | null {
  if (/^file:/i.test(uri)) {
    try { return fileURLToPath(uri); } catch { return null; }
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(uri)) return null;
  try { return decodeURIComponent(uri); } catch { return uri; }
}

/** `normalizePath` in the server's normalize.ts (without its repository name step): the path the server classifies. */
function categoryPath(uri: string): string | null {
  let p = uri.trim();
  try { p = decodeURIComponent(p); } catch { /* keep as given */ }
  p = p.replace(/\\/g, '/').replace(/^file:\/\//i, '');
  p = p.replace(/^\/github\/workspace\//, '').replace(/^\/home\/runner\/work\/[^/]+\/[^/]+\//, '');
  p = p.replace(/^\.\//, '').replace(/^\/+/, '').replace(/\/{2,}/g, '/');
  return !p || p.split('/').some((s) => s === '..') ? null : p;
}

const outsideRel = (rel: string) => !rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || /^[A-Za-z]:/.test(rel);

/** The finding's file relative to the workspace (forward slashes), or why there is none. */
function locate(result: Obj, run: Obj, workspace: string): Located {
  const physical = arr(result.locations).map((l: Obj) => l?.physicalLocation).find(isObj);
  const al = isObj(physical?.artifactLocation) ? physical.artifactLocation : {};
  const fromIndex = Number.isInteger(al.index) ? arr(run.artifacts)[al.index]?.location : null;
  const loc = typeof al.uri === 'string' ? al : isObj(fromIndex) ? fromIndex : null;
  const uri = loc && typeof loc.uri === 'string' && loc.uri.trim() ? loc.uri.trim() : null;
  const rawStart = physical?.region?.startLine;
  const start = Number.isInteger(rawStart) && rawStart >= 1 ? rawStart as number : null;
  const rawEnd = physical?.region?.endLine;
  const end = start === null ? 0 : Math.min(Number.isInteger(rawEnd) && rawEnd >= start ? rawEnd : start, start + MAX_RANGE_LINES - 1);
  const located = (kind: Located['kind'], path: string | null = null): Located => ({ kind, path, categoryPath: uri ? categoryPath(uri) : null, start, end });
  if (!uri || start === null) return located('none');

  let p = uriToPath(uri);
  if (p === null) return located('outside');
  const base = typeof loc?.uriBaseId === 'string' ? run.originalUriBaseIds?.[loc.uriBaseId]?.uri : null;
  const basePath = typeof base === 'string' ? uriToPath(base) : null;
  if (!isAbsolute(p) && !p.startsWith('/') && basePath) p = resolve(workspace, basePath, p);
  // Container actions see the workspace at /github/workspace.
  p = p.replace(/^\/github\/workspace\//, '');
  const rel = relative(workspace, resolve(workspace, p));
  if (outsideRel(rel)) return located('outside');
  const path = rel.split(sep).join('/');
  if (path.split('/').includes('.git')) return located('outside');
  return located('ok', path);
}

// ---------------------------------------------------------------------------------------------
// Blame
// ---------------------------------------------------------------------------------------------
type Blamed =
  | { ok: true; commit: string; boundary: boolean; lines: string[] }
  | { ok: false; reason: 'missing' | 'binary' | 'error' | 'limit'; lineCount?: number };

/** Parses `git blame --porcelain`: each line's commit, that commit's committer time and boundary flag, and the line text. */
function parsePorcelain(out: string): Blamed {
  const commits = new Map<string, { time: number; boundary: boolean }>();
  const lines: string[] = [];
  const order: string[] = [];
  let current: string | null = null;
  for (const raw of out.split('\n')) {
    const header = /^([0-9a-f]{40,64}) \d+ \d+(?: \d+)?$/.exec(raw);
    if (header) {
      current = header[1];
      if (!commits.has(current)) commits.set(current, { time: 0, boundary: false });
      continue;
    }
    if (!current) continue;
    if (raw.startsWith('\t')) { lines.push(raw.slice(1)); order.push(current); continue; }
    const info = commits.get(current)!;
    if (raw.startsWith('committer-time ')) info.time = Number(raw.slice(15)) || 0;
    else if (raw === 'boundary') info.boundary = true;
  }
  if (!lines.length) return { ok: false, reason: 'error' };
  if (lines.some((l) => l.includes('\u0000'))) return { ok: false, reason: 'binary' };
  let best = order[0];
  for (const c of order) if (commits.get(c)!.time > commits.get(best)!.time) best = c;
  return { ok: true, commit: best, boundary: commits.get(best)!.boundary, lines };
}

function failureReason(text: string): 'missing' | 'binary' | 'error' {
  if (/no such path|has only \d+ lines?|does not exist|outside repository|no such file/i.test(text)) return 'missing';
  if (/binary/i.test(text)) return 'binary';
  return 'error';
}

/**
 * The SARIF file's content, read by the caller through the workspace file check
 * (safe-path.ts), so this function never opens a checkout file itself. Content that is not a SARIF
 * object, or a workspace where git cannot find HEAD, gives null.
 */
export async function buildBlameSidecar(sarif: Uint8Array, opts: BlameOptions): Promise<BlameSidecar | null> {
  const started = Date.now();
  // One budget per report step when the caller passes one; otherwise this file has its own.
  const budget = opts.budget ?? createBlameBudget(opts, started);
  if (budget.gitMissing) return null;
  const git = opts.git ?? execGit;
  const cwd = opts.cwd;
  // Every git call is scoped to the workspace: the checkout may belong to another user (a pipe or
  // container running as root), and safe.directory from the command line trusts only this path.
  const safeDirectory = cwd.replace(/\\/g, '/');
  // safe.bareRepository=explicit: a bare repository committed inside the checkout is never used as the repository.
  const gitRun = (args: string[], timeoutMs: number) =>
    git.run(['-c', `safe.directory=${safeDirectory}`, '-c', 'safe.bareRepository=explicit', ...args], { cwd, timeoutMs });
  const callMs = () => Math.min(MAX_CALL_MS, budget.deadline - Date.now());

  let doc: Obj;
  let sarifSha256: string;
  try {
    sarifSha256 = createHash('sha256').update(sarif).digest('hex');
    doc = JSON.parse(Buffer.from(sarif.buffer, sarif.byteOffset, sarif.byteLength).toString('utf8'));
    if (!isObj(doc)) return null;
  } catch {
    return null;
  }

  let head: string;
  let shallow: boolean;
  try {
    head = (await gitRun(['rev-parse', 'HEAD'], MAX_CALL_MS)).trim();
    if (!/^[0-9a-f]{40,64}$/.test(head)) return null;
    shallow = (await gitRun(['rev-parse', '--is-shallow-repository'], MAX_CALL_MS).catch(() => 'false')).trim() === 'true';
  } catch (e) {
    if ((e as { code?: unknown })?.code === 'ENOENT') budget.gitMissing = true;
    return null;
  }

  const cache = new Map<string, Promise<Blamed>>();
  const missingFiles = new Set<string>();
  const shallowBoundary = new Map<string, Promise<boolean>>();
  let canDeepen = shallow;

  const blameRange = (path: string, start: number, end: number): Promise<Blamed> => {
    const key = `${start},${end}\u0000${path}`;
    let hit = cache.get(key);
    if (!hit) {
      hit = (async (): Promise<Blamed> => {
        if (missingFiles.has(path)) return { ok: false, reason: 'missing' };
        const timeoutMs = callMs();
        if (timeoutMs <= 0) return { ok: false, reason: 'limit' };
        try {
          return parsePorcelain(await gitRun(['blame', '--no-textconv', '-w', '-M', '-C', '--porcelain', '-L', `${start},${end}`, head, '--', path], timeoutMs));
        } catch (e) {
          if (Date.now() >= budget.deadline) return { ok: false, reason: 'limit' };
          const stderr = e instanceof GitError ? e.stderr : '';
          if (/no such path/i.test(stderr)) missingFiles.add(path);
          const lineCount = Number(/has only (\d+) lines?/i.exec(stderr)?.[1]) || undefined;
          return { ok: false, reason: failureReason(stderr), lineCount };
        }
      })();
      cache.set(key, hit);
    }
    return hit;
  };

  /** A range that runs past the end of the file is cut to the file's last line; a start past the end is missing. */
  const blame = async (path: string, start: number, end: number): Promise<Blamed> => {
    const first = await blameRange(path, start, end);
    const lineCount = first.ok ? null : first.lineCount;
    return lineCount && start <= lineCount && end > lineCount ? blameRange(path, start, lineCount) : first;
  };

  /** A boundary commit in a shallow clone is the clone's edge when its object still names a parent (a true root has none). */
  const isShallowEdge = (commit: string, timeoutMs: number): Promise<boolean> => {
    let hit = shallowBoundary.get(commit);
    if (!hit) {
      hit = gitRun(['cat-file', 'commit', commit], timeoutMs).then((raw) => /^parent [0-9a-f]+$/m.test(raw), () => true);
      shallowBoundary.set(commit, hit);
    }
    return hit;
  };

  const deepen = async (): Promise<boolean> => {
    if (!canDeepen || budget.deepensLeft <= 0) return false;
    budget.deepensLeft--;
    try {
      // A stalled transfer (under 1 KB/s for 10 s) is given up rather than left to use the whole budget.
      await gitRun(['-c', 'http.lowSpeedLimit=1000', '-c', 'http.lowSpeedTime=10', 'fetch', `--deepen=${DEEPEN_BY}`, '--no-tags', '--quiet'], Math.max(1, budget.deadline - Date.now()));
    } catch {
      canDeepen = false;
      return false;
    }
    cache.clear();
    shallowBoundary.clear();
    return true;
  };

  /**
   * The file's lines at HEAD (`git show <head>:./<path>`: the committed file, never the working tree). Null for a file
   * that is not at HEAD, is binary, or could not be read. Callers hold one file at a time.
   */
  const linesAtHead = (path: string, timeoutMs: number): Promise<string[] | null> =>
    gitRun(['show', '--no-textconv', `${head}:./${path}`], timeoutMs).then(
      (text) => (text.includes('\u0000') ? null : text.split('\n').map((l) => l.replace(/\r$/, ''))),
      () => null,
    );
  /** Results to hash once blame is done: they are grouped by file, so each file is read once and only it is in memory. */
  const toHash: Array<{ entry: BlameResult; path: string; start: number; end: number }> = [];
  /**
   * Snippet hashes within the step's snippet allowance (none past it: the server then keeps the line-based id). A
   * range that runs past the end of the file is cut to its last line, as blame cuts it.
   */
  const hashSnippets = async () => {
    const byPath = new Map<string, typeof toHash>();
    for (const t of toHash) {
      const group = byPath.get(t.path);
      if (group) group.push(t); else byPath.set(t.path, [t]);
    }
    if (!byPath.size) return;
    const deadline = budget.snippetDeadline ??= Date.now() + budget.snippetMs;
    for (const [path, group] of byPath) {
      const timeoutMs = Math.min(MAX_CALL_MS, deadline - Date.now());
      if (budget.snippetsLeft <= 0 || timeoutMs <= 0) return;
      const counted = group.slice(0, budget.snippetsLeft);
      budget.snippetsLeft -= counted.length;
      const lines = await linesAtHead(path, timeoutMs);
      if (!lines) continue;
      // A file that ends in a newline splits into one more, empty, element that is not a line.
      const count = lines.at(-1) === '' ? lines.length - 1 : lines.length;
      for (const { entry, start, end } of counted) {
        const hash = start > count ? undefined : snippetHashOf(lines.slice(start - 1, Math.min(end, count)));
        if (hash) entry.snippetHash = hash;
      }
    }
  };

  const results: BlameResult[] = [];
  const runs = arr(doc.runs).slice(0, MAX_RUNS);
  for (let r = 0; r < runs.length; r++) {
    const run = isObj(runs[r]) ? runs[r] : {};
    const list = arr(run.results);
    for (let i = 0; i < list.length; i++) {
      const result = list[i];
      if (!isObj(result) || SKIP_KINDS.has(result.kind)) continue;
      const entry: BlameResult = { run: r, result: i, status: 'skipped' };
      results.push(entry);
      try {
        const located = locate(result, run, cwd);
        if (isDependencyResult(result, ruleFor(result, run), run, located.categoryPath, located.start)) {
          Object.assign(entry, { status: 'not_applicable', reason: 'dependency' });
          continue;
        }
        if (located.kind === 'none') { entry.reason = 'no_location'; continue; }
        if (located.kind === 'outside' || !located.path || located.start === null) { entry.reason = 'missing'; continue; }
        const { path, start, end } = { path: located.path, start: located.start, end: located.end };
        // Hashed whatever blame makes of the result (after the loop): the server names a result without SARIF
        // fingerprints by it, and never uses it for one with them.
        // Never more than the step's snippet allowance has room for, and none once its window has passed.
        // A result without a rule id is never hashed: the server names it by its line (it has no snippet id to move or hold).
        if (!hasFingerprints(result) && hasRuleId(result, run) && toHash.length < budget.snippetsLeft && (budget.snippetDeadline === null || Date.now() < budget.snippetDeadline)) {
          toHash.push({ entry, path, start, end });
        }
        if (budget.resultsLeft <= 0 || Date.now() >= budget.deadline) { entry.reason = 'limit'; continue; }
        budget.resultsLeft--;

        let blamed = await blame(path, start, end);
        while (blamed.ok && shallow && blamed.boundary) {
          const timeoutMs = callMs();
          if (timeoutMs <= 0) { entry.reason = 'limit'; break; }
          if (!(await isShallowEdge(blamed.commit, timeoutMs))) break;
          if (!(await deepen())) { entry.reason = Date.now() >= budget.deadline ? 'limit' : 'shallow'; break; }
          blamed = await blame(path, start, end);
        }
        if (entry.reason) continue;
        if (!blamed.ok) { entry.reason = blamed.reason; continue; }
        Object.assign(entry, { status: 'found', commit: blamed.commit });
      } catch {
        entry.reason = 'error';
      }
    }
  }

  try {
    await hashSnippets();
  } catch {
    // A hash is an aid to the server's finding id; without one it keeps the line-based id.
  }

  return {
    format: 'prodgator-blame', version: 1, sarifSha256, head, results,
    stats: { blamed: results.filter((e) => e.status === 'found').length, skipped: results.filter((e) => e.status === 'skipped').length, ms: Date.now() - started },
  };
}
