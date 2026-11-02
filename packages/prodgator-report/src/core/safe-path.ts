import { createHash } from 'crypto';
import { constants, promises as fs } from 'fs';
import type { FileHandle } from 'fs/promises';
import { isAbsolute, relative, resolve, sep } from 'path';

/**
 * Every file the client reads from the CI checkout goes through here. The checkout is attacker-influenced
 * (fork pull requests, malicious repository contents): a committed symlink, or a symlinked directory, can
 * point anywhere on the runner (~/.ssh, the job token file, /proc/self/environ, the runner temp directory).
 * A file is read only when its real path, after following every symlink, is inside the real path of the
 * root, and never from a .git directory (actions/checkout stores the job token in .git/config).
 *
 * Reads go through one opened handle: the real path is opened with O_NOFOLLOW (where the platform has it),
 * the handle is checked to be the same file that passed the check (by /proc/self/fd on Linux, else by
 * device and inode), and the content is read, hashed or streamed from that handle. A swap between the
 * check and the read is refused instead of followed.
 */

export type RefusalReason = 'outside' | 'git' | 'symlink' | 'missing' | 'not-file' | 'changed';
/** `message` names the file as the caller gave it and never includes file contents. */
export interface Refusal { ok: false; reason: RefusalReason; message: string }
export interface WorkspaceFile {
  /** The path as resolved against the root, before following symlinks. */
  absolute: string;
  /** Root-relative POSIX path. */
  path: string;
  /** The real path (every symlink followed), inside the real root. */
  real: string;
}
export interface PathOptions {
  /** How the file is named in messages. Defaults to the name passed in. */
  display?: string;
  /** false: refuse a symlink anywhere below the root, even one that stays inside it. */
  followLinks?: boolean;
}

const O_NOFOLLOW = (constants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
const outside = (rel: string) => !rel || rel === '..' || rel.startsWith(`..${sep}`) || rel.startsWith('../') || isAbsolute(rel) || /^[A-Za-z]:/.test(rel);
const underGit = (rel: string) => rel.split(/[\\/]/).includes('.git');
const refuse = (reason: RefusalReason, message: string): Refusal => ({ ok: false, reason, message });

/** How a matched file is named in warnings: its workspace path when it is inside, else where it is. */
export function displayName(root: string, file: string): string {
  const rel = relative(resolve(root), resolve(root, file));
  return outside(rel) ? file : rel.split(sep).join('/');
}

/** The lexical and real-path checks, without opening the file. */
export async function checkWorkspacePath(root: string, name: string, opts: PathOptions = {}): Promise<{ ok: true; file: WorkspaceFile } | Refusal> {
  const display = opts.display ?? name;
  const absolute = resolve(root, name);
  const rel = relative(resolve(root), absolute);
  if (outside(rel)) return refuse('outside', `${display} is outside the workspace`);
  const path = rel.split(sep).join('/');
  if (underGit(path)) return refuse('git', `${display} is inside a .git directory`);
  let real: string;
  let realRoot: string;
  try {
    [real, realRoot] = await Promise.all([fs.realpath(absolute), fs.realpath(root)]);
  } catch {
    return refuse('missing', `${display} was not found`);
  }
  const realRel = relative(realRoot, real);
  if (outside(realRel)) return refuse('symlink', `${display} resolves outside the workspace (symlink)`);
  if (underGit(realRel)) return refuse('git', `${display} resolves into a .git directory (symlink)`);
  if (opts.followLinks === false && realRel !== rel) return refuse('symlink', `${display} is a symlink`);
  return { ok: true, file: { absolute, path, real } };
}

/**
 * Opens a file that passed `checkWorkspacePath`, through a handle that is checked to be that file.
 * The caller owns the handle and must close it.
 */
export async function openWorkspaceFile(root: string, name: string, opts: PathOptions = {}): Promise<{ ok: true; file: WorkspaceFile; size: number; handle: FileHandle } | Refusal> {
  const display = opts.display ?? name;
  const checked = await checkWorkspacePath(root, name, opts);
  if (!checked.ok) return checked;
  const { file } = checked;
  let handle: FileHandle;
  try {
    // The real path's last component is not a symlink; O_NOFOLLOW refuses one swapped in since.
    handle = await fs.open(file.real, constants.O_RDONLY | O_NOFOLLOW);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === 'ENOENT' ? refuse('missing', `${display} was not found`) : refuse('changed', `${display} could not be opened safely`);
  }
  try {
    const st = await handle.stat();
    if (!st.isFile()) { await handle.close(); return refuse('not-file', `${display} is not a file`); }
    if (!(await sameFile(handle, st, file.real, await fs.realpath(root)))) {
      await handle.close();
      return refuse('changed', `${display} changed before it could be read (symlink)`);
    }
    return { ok: true, file, size: st.size, handle };
  } catch {
    await handle.close().catch(() => {});
    return refuse('changed', `${display} changed before it could be read (symlink)`);
  }
}

/** Whether the opened handle is still the file at `real`, inside `realRoot`. */
async function sameFile(handle: FileHandle, st: import('fs').Stats, real: string, realRoot: string): Promise<boolean> {
  // Linux: the kernel's own path for the open file, whatever happened to the names since.
  const viaProc = await fs.realpath(`/proc/self/fd/${handle.fd}`).catch(() => null);
  if (viaProc !== null) {
    const rel = relative(realRoot, viaProc);
    return viaProc === real && !outside(rel) && !underGit(rel);
  }
  // Elsewhere: the name still resolves to the same place and the same device and inode.
  const again = await fs.realpath(real).catch(() => null);
  if (again !== real) return false;
  const now = await fs.stat(real).catch(() => null);
  return !!now && now.dev === st.dev && now.ino === st.ino;
}

/** Reads a workspace file as UTF-8 through a checked handle. `maxBytes`: refuse larger files without reading them. */
export async function readWorkspaceText(root: string, name: string, opts: PathOptions & { maxBytes?: number } = {}): Promise<{ ok: true; file: WorkspaceFile; size: number; text: string | null } | Refusal> {
  const opened = await openWorkspaceFile(root, name, opts);
  if (!opened.ok) return opened;
  try {
    if (opts.maxBytes !== undefined && opened.size > opts.maxBytes) return { ok: true, file: opened.file, size: opened.size, text: null };
    return { ok: true, file: opened.file, size: opened.size, text: await opened.handle.readFile('utf8') };
  } finally {
    await opened.handle.close();
  }
}

/** SHA-256 of an open file, from its start. Leaves the handle open. */
export async function sha256Handle(handle: FileHandle): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of handle.createReadStream({ autoClose: false, start: 0 })) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/** Size and SHA-256 of a workspace file, hashed from a checked handle. */
export async function hashWorkspaceFile(root: string, name: string, opts: PathOptions = {}): Promise<{ ok: true; file: WorkspaceFile; size: number; sha256: string } | Refusal> {
  const opened = await openWorkspaceFile(root, name, opts);
  if (!opened.ok) return opened;
  try {
    return { ok: true, file: opened.file, size: opened.size, sha256: await sha256Handle(opened.handle) };
  } finally {
    await opened.handle.close();
  }
}
