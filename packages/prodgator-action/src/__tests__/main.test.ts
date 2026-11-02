import { describe, it, expect, vi, onTestFinished } from 'vitest';
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { run } from '../main';

function core(inputs: Record<string, string> = {}, getIDToken = vi.fn(async () => 'tok')) {
  return { getInput: (n: string) => inputs[n] ?? '', getIDToken, setOutput: vi.fn(), setFailed: vi.fn(), warning: vi.fn(), notice: vi.fn(), info: vi.fn(), debug: vi.fn() };
}
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
const ingest = (over: Record<string, unknown> = {}) => ({ reportId: '1-abc', runId: 'r1', attempt: 1, url: 'https://prodgator/pipelines/r1', trusted: true, uploads: [], skipped: [], warnings: [], ...over });
const env = () => ({ GITHUB_JOB: 'test', GITHUB_WORKSPACE: mkdtempSync(join(tmpdir(), 'ws-')), RUNNER_NAME: 'runner-1' });

describe('run', () => {
  it('sends the report and sets outputs', async () => {
    const c = core({ summary: '## hi' });
    const fetch = vi.fn().mockResolvedValue(ok(ingest()));
    await run({ core: c as any, fetch, sleep: async () => {}, env: env() });
    const sent = JSON.parse(fetch.mock.calls[0][1].body);
    expect(fetch.mock.calls[0][0]).toBe('https://api.prodgator.io/api/ingest/github/reports');
    expect(sent).toMatchObject({ version: 1, job: { name: 'test', runner: 'runner-1' }, summary: '## hi' });
    expect(c.getIDToken).toHaveBeenCalledWith('https://api.prodgator.io');
    expect(c.setOutput).toHaveBeenCalledWith('report-id', '1-abc');
    expect(c.setOutput).toHaveBeenCalledWith('report-url', 'https://prodgator/pipelines/r1');
    expect(c.setFailed).not.toHaveBeenCalled();
  });
  it('identifies itself with the action user agent', async () => {
    const c = core({ summary: '## hi' });
    const fetch = vi.fn().mockResolvedValue(ok(ingest()));
    await run({ core: c as any, fetch, sleep: async () => {}, env: env() });
    const init = fetch.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ 'user-agent': expect.stringMatching(/^prodgator-report-action\//) });
  });
  it('prints the replacement warning', async () => {
    const c = core();
    await run({ core: c as any, fetch: vi.fn().mockResolvedValue(ok(ingest({ warnings: ['REPORT_REPLACED_BY_OTHER_RUNNER'] }))), sleep: async () => {}, env: env() });
    expect(c.warning).toHaveBeenCalledWith(expect.stringContaining('matrix: ${{ toJSON(matrix) }}'));
  });
  it('never fails the build by default', async () => {
    const c = core();
    await run({ core: c as any, fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ code: 'INTERNAL', retryable: true, error: 'x' }), { status: 500 })), sleep: async () => {}, env: env() });
    expect(c.setFailed).not.toHaveBeenCalled();
    expect(c.warning).toHaveBeenCalledWith(expect.stringMatching(/^Prodgator report was not sent/));
  });
  it('fails the step when fail-on-error is true', async () => {
    const c = core({ 'fail-on-error': 'true' });
    await run({ core: c as any, fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ code: 'REPO_NOT_LINKED', retryable: false, error: 'not linked' }), { status: 403 })), sleep: async () => {}, env: env() });
    expect(c.setFailed).toHaveBeenCalledWith(expect.stringContaining('REPO_NOT_LINKED'));
  });
  it('explains a missing id-token permission', async () => {
    const c = core({}, vi.fn(async () => { throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable'); }));
    await run({ core: c as any, fetch: vi.fn(), sleep: async () => {}, env: env() });
    expect(c.warning).toHaveBeenCalledWith(expect.stringContaining('permissions: id-token: write'));
  });
  it('attaches the scanner file of a scan attestation, points the attestation at it and uploads it once', async () => {
    const e = env();
    writeFileSync(join(e.GITHUB_WORKSPACE, 'trivy.sarif'), JSON.stringify({ runs: [{ results: [{ level: 'error' }] }] }));
    const upload = vi.fn().mockResolvedValue(undefined);
    const fetch = vi.fn()
      .mockResolvedValueOnce(ok(ingest({ uploads: [{ artifactId: 'is', path: 'trivy.sarif', url: 'u', method: 'PUT', headers: {}, expiresAt: 'x' }] })))
      .mockResolvedValueOnce(ok({ reportId: '1-abc', results: [{ artifactId: 'is', status: 'uploaded' }] }));
    const c = core({
      attestations: JSON.stringify([{ kind: 'scan', name: 'trivy', file: 'trivy.sarif', format: 'sarif', data: { tool: 'trivy' } }]),
      artifacts: '*.sarif',
    });
    await run({ core: c as any, fetch, sleep: async () => {}, env: e, upload });
    const sent = JSON.parse(fetch.mock.calls[0][1].body);
    expect(sent.attestations).toEqual([{ kind: 'scan', name: 'trivy', sourcePath: 'trivy.sarif', data: { tool: 'trivy', artifact: 'trivy.sarif', format: 'sarif', critical: 0, high: 1, medium: 0, low: 0, suppressed: 0 } }]);
    expect(sent.artifacts).toEqual([expect.objectContaining({ path: 'trivy.sarif', contentType: 'application/sarif+json' })]);
    expect(upload).toHaveBeenCalledTimes(1);
  });
  it('sums JUnit files into one attestation named junit, or by junit-name', async () => {
    const e = env();
    mkdirSync(join(e.GITHUB_WORKSPACE, 'reports'));
    const xml = '<testsuite name="s"><testcase name="t"/></testsuite>';
    writeFileSync(join(e.GITHUB_WORKSPACE, 'reports', 'a.xml'), xml);
    writeFileSync(join(e.GITHUB_WORKSPACE, 'reports', 'b.xml'), xml);
    const send = async (inputs: Record<string, string>) => {
      const fetch = vi.fn().mockResolvedValue(ok(ingest()));
      await run({ core: core({ junit: 'reports/*.xml', ...inputs }) as any, fetch, sleep: async () => {}, env: e });
      return JSON.parse(fetch.mock.calls[0][1].body).attestations;
    };
    expect(await send({})).toEqual([expect.objectContaining({ kind: 'test-results', name: 'junit', sourcePath: 'reports/*.xml', data: expect.objectContaining({ passed: 2 }) })]);
    expect(await send({ 'junit-name': 'unit' })).toEqual([expect.objectContaining({ name: 'unit', sourcePath: 'reports/*.xml' })]);
  });
  it('blames SARIF scans unless the blame input is false', async () => {
    // Git never looks above the temp directory, so the workspace is no git checkout.
    vi.stubEnv('GIT_CEILING_DIRECTORIES', realpathSync(tmpdir()));
    onTestFinished(() => { vi.unstubAllEnvs(); });
    for (const [blame, warned] of [['', true], ['false', false]] as const) {
      const e = env();
      writeFileSync(join(e.GITHUB_WORKSPACE, 'scan.sarif'), JSON.stringify({ runs: [{ results: [] }] }));
      const c = core({ blame, attestations: JSON.stringify([{ kind: 'scan', name: 's', file: 'scan.sarif', format: 'sarif', data: { tool: 's' } }]) });
      await run({ core: c as any, fetch: vi.fn().mockResolvedValue(ok(ingest())), sleep: async () => {}, env: e });
      // A temporary directory is no git checkout, so blame is skipped with a warning and the report still goes out.
      expect(c.warning.mock.calls.some(([m]) => /blame data was not added/.test(String(m)))).toBe(warned);
      expect(c.setOutput).toHaveBeenCalledWith('report-id', '1-abc');
    }
  });
  it('warns and still sends when a scanner file is missing', async () => {
    const c = core({ attestations: JSON.stringify([{ kind: 'scan', name: 'trivy', file: 'missing.sarif', data: { tool: 'trivy', critical: 0, high: 0, medium: 0, low: 0 } }]) });
    const fetch = vi.fn().mockResolvedValue(ok(ingest()));
    await run({ core: c as any, fetch, sleep: async () => {}, env: env() });
    expect(c.warning).toHaveBeenCalledWith(expect.stringContaining('missing.sarif was not found'));
    expect(JSON.parse(fetch.mock.calls[0][1].body).artifacts).toEqual([]);
    expect(c.setOutput).toHaveBeenCalledWith('report-id', '1-abc');
  });
  it('uploads offered slots and completes only the uploaded ones', async () => {
    const e = env();
    writeFileSync(join(e.GITHUB_WORKSPACE, 'a.txt'), 'a');
    writeFileSync(join(e.GITHUB_WORKSPACE, 'b.txt'), 'b');
    const upload = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('b.txt: upload refused (BadDigest)'));
    const fetch = vi.fn()
      .mockResolvedValueOnce(ok(ingest({ uploads: [{ artifactId: 'ia', path: 'a.txt', url: 'u', method: 'PUT', headers: {}, expiresAt: 'x' }, { artifactId: 'ib', path: 'b.txt', url: 'u', method: 'PUT', headers: {}, expiresAt: 'x' }], skipped: [{ path: 'c.bin', reason: 'too_large' }] })))
      .mockResolvedValueOnce(ok({ reportId: '1-abc', results: [{ artifactId: 'ia', status: 'uploaded' }] }));
    const c = core({ artifacts: '*.txt' });
    await run({ core: c as any, fetch, sleep: async () => {}, env: e, upload });
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ artifactIds: ['ia'] });
    expect(fetch.mock.calls[1][0]).toBe('https://api.prodgator.io/api/ingest/github/reports/1-abc/complete');
    expect(c.warning).toHaveBeenCalledWith(expect.stringContaining('BadDigest'));
    expect(c.warning).toHaveBeenCalledWith(expect.stringContaining('c.bin'));
  });
  it('uploads the ownership file with an ownership attestation', async () => {
    const e = env();
    mkdirSync(join(e.GITHUB_WORKSPACE, '.github'));
    writeFileSync(join(e.GITHUB_WORKSPACE, '.github', 'CODEOWNERS'), '* @acme/everyone\n');
    const upload = vi.fn().mockResolvedValue(undefined);
    const fetch = vi.fn()
      .mockResolvedValueOnce(ok(ingest({ uploads: [{ artifactId: 'io', path: '.github/CODEOWNERS', url: 'u', method: 'PUT', headers: {}, expiresAt: 'x' }] })))
      .mockResolvedValueOnce(ok({ reportId: '1-abc', results: [{ artifactId: 'io', status: 'uploaded' }] }));
    const c = core({ ownership: '.github/CODEOWNERS' });
    await run({ core: c as any, fetch, sleep: async () => {}, env: e, upload });
    const sent = JSON.parse(fetch.mock.calls[0][1].body);
    expect(sent.attestations).toEqual([{ kind: 'ownership', name: 'codeowners', status: 'info', data: { format: 'codeowners', artifact: '.github/CODEOWNERS' } }]);
    expect(sent.artifacts).toEqual([expect.objectContaining({ path: '.github/CODEOWNERS', contentType: 'text/plain' })]);
    expect(upload).toHaveBeenCalledTimes(1);
    expect(c.warning).not.toHaveBeenCalled();
  });
  it('sends a JSON ownership file as json, and warns when the file is missing', async () => {
    const e = env();
    writeFileSync(join(e.GITHUB_WORKSPACE, 'owners.json'), '{"version":1,"rules":[]}');
    const fetch = vi.fn().mockResolvedValue(ok(ingest()));
    await run({ core: core({ ownership: 'owners.json' }) as any, fetch, sleep: async () => {}, env: e });
    expect(JSON.parse(fetch.mock.calls[0][1].body).attestations[0]).toMatchObject({ kind: 'ownership', data: { format: 'json', artifact: 'owners.json' } });
    const c = core({ ownership: 'missing/CODEOWNERS' });
    const f2 = vi.fn().mockResolvedValue(ok(ingest()));
    await run({ core: c as any, fetch: f2, sleep: async () => {}, env: env() });
    expect(c.warning).toHaveBeenCalledWith('missing/CODEOWNERS was not found (or is empty); no ownership report was sent');
    expect(JSON.parse(f2.mock.calls[0][1].body).attestations).toEqual([]);
  });
});
