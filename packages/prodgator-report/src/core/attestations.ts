import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import { tmpdir } from 'os';
import { extname, join } from 'path';
import { BLAME_SIDECAR_SUFFIX, buildBlameSidecar, createBlameBudget, type BlameBudget, type BlameLimits } from './blame';
import type { ArtifactFile } from './artifacts';
import { openWorkspaceFile, readWorkspaceText, sha256Handle } from './safe-path';
import type { AttestationInput } from './types';
import { provenanceData } from './provenance';
import { cleanSourcePath } from './source-path';
import { sarifCounts, type SarifCounts } from './sarif-counts';

export { sarifCounts, type SarifCounts } from './sarif-counts';

const KINDS = ['test-results', 'coverage', 'sbom', 'scan', 'custom', 'provenance'];

/**
 * The input is inline JSON or a path to a JSON file. A file outside the workspace, or whose real path is
 * outside it (a symlink), fails the report the same way an unreadable file does.
 */
export async function parseAttestationsInput(value: string | null, workspace: string): Promise<AttestationInput[]> {
  if (!value) return [];
  let text = value;
  if (!/^\s*[[{]/.test(value)) {
    const read = await readWorkspaceText(workspace, value.trim());
    if (!read.ok) throw new Error(`attestations file ${read.message}; it was not read`);
    text = read.text ?? '';
  }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new Error('attestations must be JSON (inline, or a path to a JSON file)'); }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  return Promise.all(list.map(async (a: any, i) => {
    if (!a || typeof a !== 'object' || !KINDS.includes(a.kind) || typeof a.name !== 'string' || !a.data || typeof a.data !== 'object') {
      throw new Error(`attestations[${i}] needs a kind (${KINDS.join(', ')}), a name and a data object`);
    }
    return (a.kind === 'provenance' ? { ...a, data: await provenanceData(a.data, workspace) } : a) as AttestationInput;
  }));
}

// Addendum (2026-09-28, plan 04 task 12): a scan/sbom attestation entry in the `attestations`
// input may carry its own `file` (a path in the workspace) and `format`. When it does, the
// action uploads that raw scanner file as an artifact in the same report (reusing the artifact
// upload path) and points the attestation's `data.artifact` at it, mirroring how the server
// resolves `sbom.artifact` / `scan.artifact` (infra/lambda/shared/run-reports/artifacts.ts) by
// matching an uploaded artifact's workspace-relative path. `file` and `format` are action-only
// instructions: they never reach the server themselves.
export type ScanFileFormat = 'sarif' | 'cyclonedx' | 'spdx' | 'grype-json' | 'trivy-json' | 'other';
const SCAN_FILE_FORMATS: ScanFileFormat[] = ['sarif', 'cyclonedx', 'spdx', 'grype-json', 'trivy-json', 'other'];
/** Printed when a scan attestation's data.mode is neither `full` nor `diff`. */
export const SCAN_MODE_WARNING = 'data.mode must be "full" or "diff"; ignored';

// Mirrors junit.ts's MAX_FILE_BYTES: both guard the same shape of operation, a full in-memory
// read of a CI-supplied file to compute counts in-process. A SARIF file
// over this size is skipped for counting (a warning is emitted) rather than read fully into
// memory; the raw file is still attached as a report artifact via the streamed, presigned
// upload path elsewhere, which this limit does not touch.
export const MAX_SARIF_BYTES = 50 * 1024 * 1024;

function contentTypeForScanFile(format: ScanFileFormat | undefined, path: string): string {
  if (format === 'sarif') return 'application/sarif+json';
  if (format === 'cyclonedx') return 'application/vnd.cyclonedx+json';
  if (format === 'spdx') return 'application/spdx+json';
  return extname(path).toLowerCase() === '.json' ? 'application/json' : 'application/octet-stream';
}

/** Printed when an attestation's data names a blame sidecar: only this client sets data.blame. */
export const BLAME_INPUT_WARNING = 'data.blame is set by the report client itself; the value given was ignored';
/** A file whose path ends in the sidecar suffix is never sent as a scan file: that name is reserved for blame data. */
const isReservedSidecarPath = (path: string) => path.toLowerCase().endsWith(BLAME_SIDECAR_SUFFIX);

/** Printed once per report step when git is not installed, instead of a warning per SARIF scan. */
export const BLAME_NO_GIT_NOTE = 'git is not installed, so code findings were sent without blame data.';

/** Printed once per report step when a SARIF file is too large to read for blame. */
export const blameTooLargeWarning = (file: string) =>
  `${file} is too large to add blame data to (over ${MAX_SARIF_BYTES} bytes), so its code findings were sent without it`;

/**
 * Blame sidecars for one report step: one shared budget (60 s, 500 blamed results, 3 deepens in all)
 * and one directory this client creates under the OS temp directory. A sidecar is never written into
 * the checkout, where a committed symlink could point the write at a runner file; it is created with
 * O_EXCL in that new directory and published under `{sarif path}.prodgator-blame.json`.
 */
class BlameSidecars {
  private dir: string | null = null;
  private count = 0;
  readonly budget: BlameBudget;
  constructor(limits: BlameLimits, private readonly build: typeof buildBlameSidecar) {
    this.budget = createBlameBudget(limits);
  }

  /** The sidecar as an artifact, or why there is none (null when git is not installed: the note covers it). */
  async add(sarif: Uint8Array, path: string, workspace: string): Promise<ArtifactFile | string | null> {
    let sidecar: Awaited<ReturnType<typeof buildBlameSidecar>>;
    try {
      sidecar = await this.build(sarif, { cwd: workspace, budget: this.budget });
    } catch {
      return 'blame data was not added (blame stopped with an error)';
    }
    if (this.budget.gitMissing) return null;
    if (!sidecar) return 'blame data was not added (the workspace is not a git checkout, or the SARIF file could not be read)';
    try {
      this.dir ??= await fs.mkdtemp(join(tmpdir(), 'prodgator-blame-'));
      const name = `${++this.count}${BLAME_SIDECAR_SUFFIX}`;
      const target = join(this.dir, name);
      const text = JSON.stringify(sidecar);
      await fs.writeFile(target, text, { flag: 'wx' });
      return {
        // Uploaded from the directory this client made (its own root for the upload check), never from the checkout.
        path: path + BLAME_SIDECAR_SUFFIX, absolute: target, workspace: this.dir, source: name,
        size: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex'), contentType: 'application/json',
      };
    } catch {
      return 'blame data was not added (the blame file could not be written)';
    }
  }

  /** Removes the temporary directory (best effort). Call after the uploads. */
  async cleanup(): Promise<void> {
    const dir = this.dir;
    this.dir = null;
    if (dir) await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

export interface ResolveAttestationFilesResult {
  attestations: AttestationInput[]; files: ArtifactFile[]; warnings: string[];
  /** Quiet information for the log (not warnings). */
  notes: string[];
  /** Removes the temporary blame sidecars; call after the uploads (best effort, never throws). */
  cleanup: () => Promise<void>;
}

interface ResolveDeps {
  /** Blame code findings of SARIF scans and upload the sidecar (Plan 18 Task 18). Off unless the caller turns it on; limits are for tests. */
  blame?: boolean | BlameLimits;
  buildBlameSidecar?: typeof buildBlameSidecar;
}

export async function resolveAttestationFiles(
  attestations: AttestationInput[],
  workspace: string,
  deps: ResolveDeps = {},
): Promise<ResolveAttestationFilesResult> {
  const blame = deps.blame ? new BlameSidecars(deps.blame === true ? {} : deps.blame, deps.buildBlameSidecar ?? buildBlameSidecar) : null;
  try {
    return await resolveFiles(attestations, workspace, blame);
  } catch (e) {
    // The caller never gets a cleanup function when this throws, so remove the sidecars here.
    await blame?.cleanup();
    throw e;
  }
}

async function resolveFiles(
  attestations: AttestationInput[], workspace: string, blame: BlameSidecars | null,
): Promise<ResolveAttestationFilesResult> {
  const files: ArtifactFile[] = [];
  const warnings: string[] = [];
  const out: AttestationInput[] = [];
  // Said once per report step, for the first SARIF file too large to blame.
  let warnedTooLargeForBlame = false;

  for (const input of attestations) {
    let a = input;
    // Only this client names a sidecar; a blame key in the input could point the server at any uploaded file.
    if ('blame' in a.data) {
      const { blame: _given, ...rest } = a.data as Record<string, unknown>;
      a = { ...a, data: rest } as AttestationInput;
      warnings.push(BLAME_INPUT_WARNING);
    }
    // A scan's data.mode is `full` or `diff`; anything else is dropped (the report is never failed over it).
    if (a.kind === 'scan' && 'mode' in a.data && a.data.mode !== 'full' && a.data.mode !== 'diff') {
      const { mode: _ignored, ...rest } = a.data as Record<string, unknown>;
      a = { ...a, data: rest } as AttestationInput;
      warnings.push(SCAN_MODE_WARNING);
    }
    // A sourcePath from the input is cleaned (workspace-relative, POSIX); one that cannot be is dropped, never failing the report.
    if ('sourcePath' in a && (a as { sourcePath?: unknown }).sourcePath !== undefined) {
      const cleaned = cleanSourcePath(workspace, (a as { sourcePath?: unknown }).sourcePath);
      const { sourcePath: _given, ...rest } = a as AttestationInput & { sourcePath?: unknown };
      a = (cleaned.ok ? { ...rest, sourcePath: cleaned.path } : rest) as AttestationInput;
      if (!cleaned.ok) warnings.push(`sourcePath of "${a.name}" ${cleaned.reason}; ignored`);
    }
    const file = (a as unknown as { file?: unknown }).file;
    if ((a.kind !== 'scan' && a.kind !== 'sbom') || typeof file !== 'string' || !file.trim()) { out.push(a); continue; }

    const format = (a as unknown as { format?: unknown }).format;
    const scanFormat = typeof format === 'string' && (SCAN_FILE_FORMATS as string[]).includes(format) ? (format as ScanFileFormat) : undefined;
    const wantCounts = a.kind === 'scan' && scanFormat === 'sarif' && a.data.critical === undefined && a.data.high === undefined && a.data.medium === undefined && a.data.low === undefined;
    const notAttached = `and was not attached to "${a.name}"`;
    const wantBlame = !!blame && a.kind === 'scan' && scanFormat === 'sarif';

    // One checked handle: the hash, the counts and (later) the upload all come from the file that passed the check.
    const opened = await openWorkspaceFile(workspace, file);
    if (!opened.ok) {
      const missing = opened.reason === 'missing' || opened.reason === 'not-file';
      warnings.push(missing ? `${file} was not found (or is empty) ${notAttached}` : `${opened.message} ${notAttached}`);
      out.push(a);
      continue;
    }
    // Checked on the path as it would be published (normalized by the workspace check), not as it was written.
    if (isReservedSidecarPath(opened.file.path)) {
      await opened.handle.close();
      warnings.push(`${opened.file.path} ends in ${BLAME_SIDECAR_SUFFIX}, a name reserved for blame data, ${notAttached}`);
      out.push(a);
      continue;
    }
    let sha256: string;
    let counts: SarifCounts | null = null;
    // Blame reads the same bytes as the hash, from the checked handle; it never opens the file itself.
    let sarifBytes: Buffer | null = null;
    try {
      if (opened.size === 0) {
        warnings.push(`${file} was not found (or is empty) ${notAttached}`);
        out.push(a);
        continue;
      }
      if ((wantCounts || wantBlame) && opened.size <= MAX_SARIF_BYTES) {
        const bytes = await opened.handle.readFile();
        sha256 = createHash('sha256').update(bytes).digest('hex');
        if (wantCounts) counts = sarifCounts(bytes.toString('utf8'));
        if (wantBlame) sarifBytes = bytes;
      } else {
        sha256 = await sha256Handle(opened.handle);
      }
    } finally {
      await opened.handle.close();
    }
    const { path, absolute } = opened.file;
    files.push({ path, absolute, workspace, size: opened.size, sha256, contentType: contentTypeForScanFile(scanFormat, path) });

    const data: Record<string, unknown> = { ...a.data, artifact: path };
    if (a.kind === 'scan' && scanFormat) data.format = scanFormat;
    if (counts) Object.assign(data, counts);
    else if (wantCounts) warnings.push(`${file} is too large to compute SARIF counts from (over ${MAX_SARIF_BYTES} bytes); skipping`);
    if (wantBlame && opened.size > MAX_SARIF_BYTES && !warnedTooLargeForBlame) {
      warnedTooLargeForBlame = true;
      warnings.push(blameTooLargeWarning(file));
    }
    if (blame && sarifBytes) {
      const sidecar = await blame.add(sarifBytes, path, workspace);
      if (typeof sidecar === 'string') warnings.push(`${file}: ${sidecar}`);
      // Two sidecars, or a sidecar and another file, never share a published path.
      else if (sidecar && files.some((f) => f.path === sidecar.path)) warnings.push(`${file}: blame data was not added (${sidecar.path} is already in this report)`);
      else if (sidecar) { files.push(sidecar); data.blame = sidecar.path; }
    }
    // Only a path the client can vouch for is sent: a given one was cleaned above, the file's own path is cleaned here (an artifact path can be 512 characters).
    const fallback = cleanSourcePath(workspace, path);
    const sourcePath = a.sourcePath ?? (fallback.ok ? fallback.path : undefined);
    out.push({ kind: a.kind, name: a.name, status: a.status, data, ...(sourcePath ? { sourcePath } : {}) });
  }

  const notes = blame?.budget.gitMissing ? [BLAME_NO_GIT_NOTE] : [];
  return { attestations: out, files, warnings, notes, cleanup: async () => { await blame?.cleanup(); } };
}
