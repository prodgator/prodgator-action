import { extname } from 'path';
import { BLAME_SIDECAR_SUFFIX } from './blame';
import { checkWorkspacePath, displayName, hashWorkspaceFile } from './safe-path';
import type { ArtifactRequest, GlobFn } from './types';

/**
 * `workspace` is kept so the upload can check the file again right before it streams it. `source` is the
 * file's name under `workspace` when it differs from the published `path`: a file the client wrote itself
 * (a blame sidecar) lives in a directory the client created, which is then its `workspace` for that check.
 */
export interface ArtifactFile extends ArtifactRequest { absolute: string; workspace: string; source?: string }
export const MAX_ARTIFACT_FILES = 50;

const TYPES: Record<string, string> = {
  '.zip': 'application/zip', '.gz': 'application/gzip', '.tgz': 'application/gzip', '.tar': 'application/x-tar',
  '.json': 'application/json', '.xml': 'application/xml', '.pdf': 'application/pdf',
  '.txt': 'text/plain', '.log': 'text/plain', '.info': 'text/plain', '.md': 'text/markdown', '.csv': 'text/csv',
  '.html': 'text/html', '.htm': 'text/html', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml',
};
export const contentTypeFor = (path: string) => TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream';

/**
 * Matched files are checked by safe-path: a committed symlink can point anywhere on the runner (the home
 * directory, the runner's temp files), so the file's real path must stay in the workspace; and nothing
 * under a .git directory is sent, because actions/checkout stores the job token in .git/config.
 */
export async function collectArtifacts(patterns: string[], workspace: string, deps: { glob: GlobFn }) {
  const warnings: string[] = [];
  if (!patterns.length) return { files: [] as ArtifactFile[], warnings };
  const find = deps.glob;
  const inside: Array<{ absolute: string; path: string }> = [];
  for (const absolute of [...new Set(await find(patterns))]) {
    const checked = await checkWorkspacePath(workspace, absolute, { display: displayName(workspace, absolute) });
    if (!checked.ok) {
      if (checked.reason !== 'missing') warnings.push(`${checked.message} and was not uploaded`);
      continue;
    }
    // The sidecar suffix is reserved for blame data the client writes itself.
    if (checked.file.path.toLowerCase().endsWith(BLAME_SIDECAR_SUFFIX)) {
      warnings.push(`${checked.file.path} ends in ${BLAME_SIDECAR_SUFFIX}, a name reserved for blame data, and was not uploaded`);
      continue;
    }
    inside.push({ absolute: checked.file.absolute, path: checked.file.path });
  }
  inside.sort((a, b) => a.path.localeCompare(b.path));
  if (inside.length > MAX_ARTIFACT_FILES) warnings.push(`${inside.length} files matched; only the first ${MAX_ARTIFACT_FILES} are uploaded`);
  const files: ArtifactFile[] = [];
  for (const f of inside.slice(0, MAX_ARTIFACT_FILES)) {
    const hashed = await hashWorkspaceFile(workspace, f.path);
    if (!hashed.ok) {
      if (hashed.reason !== 'missing' && hashed.reason !== 'not-file') warnings.push(`${hashed.message} and was not uploaded`);
      continue;
    }
    if (hashed.size === 0) continue;
    files.push({ path: f.path, absolute: f.absolute, workspace, size: hashed.size, sha256: hashed.sha256, contentType: contentTypeFor(f.path) });
  }
  return { files, warnings };
}
