import { promises as fs } from 'fs';
import { basename, dirname, join } from 'path';
import * as core from '@actions/core';
import { MAX_SUMMARY_BYTES, readWorkspaceText, truncateUtf8 } from '../../prodgator-report/src/core';

const SCRUBBED = '-scrubbed';

/**
 * The markdown earlier steps of this job wrote to their own $GITHUB_STEP_SUMMARY files (runner layout, see R23).
 *
 * When a step ends, the runner writes a secret-masked copy of its summary, `step_summary_<id>-scrubbed`, next to
 * the raw `step_summary_<id>` and uploads only that copy. The raw file stays on disk, so reading both sent every
 * summary twice, once unmasked. Only the scrubbed copies are read: exactly what GitHub shows for the job.
 *
 * The runner writes plain files there. A symlink was planted by a step, so it is skipped, even one that points
 * at a file next to it (a raw, unmasked summary).
 */
export async function collectJobSummary(env: NodeJS.ProcessEnv = process.env, warn: (message: string) => void = core.warning): Promise<string | null> {
  const own = env.GITHUB_STEP_SUMMARY;
  if (!own) return null;
  const dir = dirname(own);
  let names: string[];
  try { names = await fs.readdir(dir); } catch { core.debug(`no step summary directory at ${dir}`); return null; }
  const ownName = basename(own);
  const files = await Promise.all(names
    .filter((n) => n.startsWith('step_summary_') && n.endsWith(SCRUBBED) && n !== ownName + SCRUBBED)
    .map(async (n) => ({ n, stat: await fs.lstat(join(dir, n)) })));
  const parts: string[] = [];
  for (const f of files.filter((f) => !f.stat.isDirectory()).sort((a, b) => a.stat.mtimeMs - b.stat.mtimeMs || a.n.localeCompare(b.n))) {
    const read = await readWorkspaceText(dir, f.n, { followLinks: false });
    if (!read.ok) {
      if (read.reason !== 'missing') warn(`Skipped the step summary ${f.n}: it is not a plain file in the runner's summary directory.`);
      continue;
    }
    if (read.text) parts.push(read.text.trim());
  }
  const joined = parts.filter(Boolean).join('\n\n');
  return joined ? truncateUtf8(joined, MAX_SUMMARY_BYTES).text : null;
}

/**
 * The `summary-file` input is read only when its real path is in the workspace: a relative path is taken
 * from the workspace, and a file that is (or sits under) a symlink to somewhere else is skipped with a warning.
 */
export async function resolveSummary(
  inputs: { summary: string | null; summaryFile: string | null },
  env: NodeJS.ProcessEnv = process.env,
  opts: { workspace: string; warn: (message: string) => void } = { workspace: env.GITHUB_WORKSPACE ?? process.cwd(), warn: core.warning },
): Promise<string | null> {
  if (inputs.summary) return truncateUtf8(inputs.summary, MAX_SUMMARY_BYTES).text;
  if (inputs.summaryFile) {
    const read = await readWorkspaceText(opts.workspace, inputs.summaryFile, { display: `summary-file ${inputs.summaryFile}` });
    if (read.ok) return truncateUtf8(read.text ?? '', MAX_SUMMARY_BYTES).text;
    // As before: a summary file that is not there fails the report (fail-on-error decides how loudly).
    if (read.reason === 'missing') throw new Error(read.message);
    opts.warn(`${read.message}; sending the report without a summary.`);
    return null;
  }
  return collectJobSummary(env, opts.warn);
}
