import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, symlinkSync, writeFileSync, utimesSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileLinks, linkDir, runnerSecret, SECRET } from '../../../prodgator-report/src/core/__tests__/symlinks';
import { collectJobSummary, resolveSummary } from '../summary';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'runner-')); });
const step = (name: string, text: string, mtime: number) => { const p = join(dir, name); writeFileSync(p, text); utimesSync(p, mtime, mtime); return p; };

// The runner leaves each finished step's raw `step_summary_<id>` in place and writes the secret-masked
// `step_summary_<id>-scrubbed` copy next to it. The running step has only its raw file.
const finished = (id: string, raw: string, scrubbed: string, mtime: number) => {
  step(`step_summary_${id}`, raw, mtime);
  step(`step_summary_${id}-scrubbed`, scrubbed, mtime + 1);
};

describe('collectJobSummary', () => {
  it('joins earlier steps in order and skips its own and empty files', async () => {
    finished('b', '## Build\nok', '## Build\nok', 100);
    finished('a', '## Setup', '## Setup', 50);
    step('step_summary_empty', '', 120);
    step('set_env_x', 'NOT A SUMMARY', 130);
    const own = step('step_summary_self', '', 200);
    expect(await collectJobSummary({ GITHUB_STEP_SUMMARY: own })).toBe('## Setup\n\n## Build\nok');
  });
  it('sends each step summary once, from the masked copy, not the raw file beside it', async () => {
    finished('deploy', '## CDK Outputs (Dev)\ntoken=hunter2', '## CDK Outputs (Dev)\ntoken=***', 100);
    const own = step('step_summary_self', 'written by this step', 200);
    const summary = await collectJobSummary({ GITHUB_STEP_SUMMARY: own });
    expect(summary).toBe('## CDK Outputs (Dev)\ntoken=***');
    expect(summary).not.toContain('hunter2');
  });
  it('skips a raw summary the runner did not publish (no masked copy)', async () => {
    step('step_summary_toolarge', 'never masked', 100);
    const own = step('step_summary_self', '', 200);
    expect(await collectJobSummary({ GITHUB_STEP_SUMMARY: own })).toBeNull();
  });
  it('returns null outside a runner', async () => {
    expect(await collectJobSummary({})).toBeNull();
    expect(await collectJobSummary({ GITHUB_STEP_SUMMARY: join(dir, 'missing', 'x') })).toBeNull();
  });
});

describe('resolveSummary', () => {
  it('prefers the inline input, then the file, then collection', async () => {
    const own = step('step_summary_self', '', 200);
    finished('a', 'collected', 'collected', 50);
    const file = join(dir, 'mine.md');
    writeFileSync(file, 'from file');
    expect(await resolveSummary({ summary: 'inline', summaryFile: file }, { GITHUB_STEP_SUMMARY: own }, { workspace: dir, warn: () => {} })).toBe('inline');
    expect(await resolveSummary({ summary: null, summaryFile: file }, { GITHUB_STEP_SUMMARY: own }, { workspace: dir, warn: () => {} })).toBe('from file');
    expect(await resolveSummary({ summary: null, summaryFile: null }, { GITHUB_STEP_SUMMARY: own }, { workspace: dir, warn: () => {} })).toBe('collected');
  });
});

// The summary file is a path in an attacker-influenced checkout; the step summaries are runner files.
describe('summary files that point elsewhere', () => {
  const ws = () => mkdtempSync(join(tmpdir(), 'ws-'));
  const run = async (summaryFile: string, workspace: string) => {
    const warnings: string[] = [];
    const summary = await resolveSummary({ summary: null, summaryFile }, {}, { workspace, warn: (m) => warnings.push(m) });
    return { summary, warnings };
  };
  it('reads a summary file relative to the workspace', async () => {
    const w = ws();
    writeFileSync(join(w, 'summary.md'), '## ok');
    expect(await run('summary.md', w)).toEqual({ summary: '## ok', warnings: [] });
  });
  it('skips an absolute summary file outside the workspace', async () => {
    const secret = runnerSecret();
    const r = await run(secret, ws());
    expect(r.summary).toBeNull();
    expect(r.warnings).toEqual([`summary-file ${secret} is outside the workspace; sending the report without a summary.`]);
  });
  it('skips a summary file in a symlinked directory', async () => {
    const w = ws();
    linkDir(dirname(runnerSecret('summary.md')), join(w, 'out'));
    const r = await run('out/summary.md', w);
    expect(r.summary).toBeNull();
    expect(r.warnings).toEqual(['summary-file out/summary.md resolves outside the workspace (symlink); sending the report without a summary.']);
  });
  it.skipIf(!fileLinks)('skips a summary file that is a symlink to a runner file', async () => {
    const w = ws();
    symlinkSync(runnerSecret(), join(w, 'summary.md'));
    const r = await run('summary.md', w);
    expect(r.summary).toBeNull();
    expect(JSON.stringify(r)).not.toContain(SECRET);
  });
  it.skipIf(!fileLinks)('skips a step summary that is a symlink, even to a file next to it', async () => {
    finished('a', '## Build', '## Build', 50);
    step('step_summary_raw', 'token=hunter2', 60);
    symlinkSync(join(dir, 'step_summary_raw'), join(dir, 'step_summary_x-scrubbed'));
    symlinkSync(runnerSecret(), join(dir, 'step_summary_y-scrubbed'));
    const own = step('step_summary_self', '', 200);
    const warnings: string[] = [];
    const summary = await collectJobSummary({ GITHUB_STEP_SUMMARY: own }, (m) => warnings.push(m));
    expect(summary).toBe('## Build');
    expect(warnings).toHaveLength(2);
    expect(JSON.stringify(warnings)).not.toContain(SECRET);
  });
});
