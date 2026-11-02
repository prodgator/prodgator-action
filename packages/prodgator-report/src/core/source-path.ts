import { posix, resolve } from 'path';

export const MAX_SOURCE_PATH_LENGTH = 200;
export type CleanSourcePath = { ok: true; path: string } | { ok: false; reason: string };

/**
 * A `sourcePath` names where an attestation came from: a workspace-relative POSIX path, or a glob pattern
 * as text. It is never absolute and never leaves the workspace. An absolute path inside the workspace
 * becomes relative; one outside it, or a `..` escape, is refused. Backslashes count as separators.
 */
export function cleanSourcePath(workspace: string, value: unknown): CleanSourcePath {
  if (typeof value !== 'string') return { ok: false, reason: 'is not text' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) return { ok: false, reason: 'contains a control character' };
  let text = value.trim().replace(/\\/g, '/');
  if (!text) return { ok: false, reason: 'is empty' };
  if (text.startsWith('/') || /^[A-Za-z]:\//.test(text)) {
    const root = resolve(workspace).replace(/\\/g, '/').replace(/\/+$/, '');
    const insensitive = process.platform === 'win32';
    const norm = (s: string) => (insensitive ? s.toLowerCase() : s);
    if (!norm(text).startsWith(`${norm(root)}/`)) return { ok: false, reason: 'is outside the workspace' };
    text = text.slice(root.length + 1);
  }
  const segments = text.split('/').filter((s) => s !== '' && s !== '.');
  if (segments.includes('..')) return { ok: false, reason: 'leaves the workspace' };
  if (segments.includes('.git')) return { ok: false, reason: 'is inside a .git directory' };
  const path = posix.join(...segments);
  if (!segments.length) return { ok: false, reason: 'is empty' };
  if (path.length > MAX_SOURCE_PATH_LENGTH) return { ok: false, reason: `is longer than ${MAX_SOURCE_PATH_LENGTH} characters` };
  return { ok: true, path };
}
