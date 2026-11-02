import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { isAbsolute, join } from 'path';
import { readInputs } from './inputs';
import { resolveSummary } from './summary';
import { ownershipFile } from './ownership';
import {
  junitAttestations, coverageAttestations, parseAttestationsInput, resolveAttestationFiles, collectArtifacts, MAX_ARTIFACT_FILES,
  buildIngestRequest, completeReport, sendReport, uploadFile, ReportError,
  type ArtifactFile, type ClientDeps,
} from '../../prodgator-report/src/core';

declare const ACTION_VERSION: string;

type CoreLike = Pick<typeof core, 'getInput' | 'getIDToken' | 'setOutput' | 'setFailed' | 'warning' | 'notice' | 'info' | 'debug'>;
export interface MainDeps { core?: CoreLike; fetch?: typeof fetch; sleep?: (ms: number) => Promise<void>; upload?: typeof uploadFile; env?: NodeJS.ProcessEnv }

const actionsGlob = async (p: string[]) => (await glob.create(p.join('\n'), { matchDirectories: false })).glob();

const WARNINGS: Record<string, string> = {
  REPORT_REPLACED_BY_OTHER_RUNNER: 'Another job leg with the same job and report name replaced this report. In matrix jobs add `matrix: ${{ toJSON(matrix) }}` to the Prodgator report step.',
};
const SKIPPED: Record<string, string> = {
  too_large: 'larger than your plan allows per file',
  run_quota: "this run's artifact storage is full",
  monthly_quota: "your organization's monthly upload allowance is used up",
};

/** Scanner files first (their attestations point at them), then globbed files; one entry per path, at most 50. */
function mergeFiles(first: ArtifactFile[], rest: ArtifactFile[], warn: (w: string) => void): ArtifactFile[] {
  const byPath = new Map<string, ArtifactFile>();
  for (const f of [...first, ...rest]) if (!byPath.has(f.path)) byPath.set(f.path, f);
  const all = [...byPath.values()];
  if (all.length > MAX_ARTIFACT_FILES) warn(`${all.length} files to upload; only the first ${MAX_ARTIFACT_FILES} are uploaded`);
  return all.slice(0, MAX_ARTIFACT_FILES);
}

export async function run(deps: MainDeps = {}): Promise<void> {
  const c = deps.core ?? core;
  const env = deps.env ?? process.env;
  let failOnError = false;
  let cleanup: (() => Promise<void>) | null = null;
  try {
    const inputs = readInputs((n) => c.getInput(n), env);
    failOnError = inputs.failOnError;
    const workspace = env.GITHUB_WORKSPACE ?? process.cwd();
    const inWorkspace = (patterns: string[]) => patterns.map((p) => (isAbsolute(p) || p.startsWith('!') ? p : join(workspace, p)));

    const summary = await resolveSummary(inputs, env, { workspace, warn: (w) => c.warning(w) });
    // A scan or sbom attestation may name its raw scanner file (`file`, `format`): it is uploaded as
    // an artifact of this report and the attestation's data.artifact points at it. A SARIF scan also
    // gets a blame sidecar (data.blame) unless the blame input is false.
    const scanned = await resolveAttestationFiles(await parseAttestationsInput(inputs.attestations, workspace), workspace, { blame: inputs.blame });
    cleanup = scanned.cleanup;
    scanned.notes.forEach((n) => c.info(n));
    const attestations = scanned.attestations;
    const owned = inputs.ownership ? await ownershipFile(inputs.ownership, workspace) : null;
    if (owned?.attestation) attestations.push(owned.attestation);
    attestations.push(...await junitAttestations(inWorkspace(inputs.junit), { glob: actionsGlob, name: inputs.junitName ?? undefined, workspace, warn: (w) => c.warning(w) }));
    attestations.push(...await coverageAttestations(inWorkspace(inputs.coverage), { glob: actionsGlob, workspace, warn: (w) => c.warning(w) }));
    // The coverage files are uploaded too, as artifacts, under the same workspace checks.
    const globbed = await collectArtifacts(inWorkspace([...inputs.coverage, ...inputs.artifacts]), workspace, { glob: actionsGlob });
    [...scanned.warnings, ...(owned?.warning ? [owned.warning] : []), ...globbed.warnings].forEach((w) => c.warning(w));
    const files = mergeFiles([...scanned.files, ...(owned?.file ? [owned.file] : [])], globbed.files, (w) => c.warning(w));

    const client: ClientDeps = {
      getToken: (aud) => c.getIDToken(aud), fetch: deps.fetch, sleep: deps.sleep,
      userAgent: `prodgator-report-action/${typeof ACTION_VERSION === 'string' ? ACTION_VERSION : 'dev'}`,
    };
    const request = buildIngestRequest({ job: { name: inputs.jobName, matrix: inputs.matrix, runner: env.RUNNER_NAME || null }, name: inputs.name, summary, attestations, files });
    const res = await sendReport(inputs.prodgatorUrl, 'github', request, inputs.audience, client);

    for (const w of res.warnings) c.warning(WARNINGS[w] ?? w);
    for (const s of res.skipped) {
      if (s.reason === 'already_uploaded') c.debug(`${s.path} was already uploaded`);
      else c.warning(`${s.path} was not uploaded: ${SKIPPED[s.reason] ?? s.reason}`);
    }
    if (!res.trusted) c.notice('Prodgator stored this report as coming from an untrusted source (fork pull request, pull_request_target or workflow_run); release policies ignore it by default.');

    const uploaded: string[] = [];
    for (const slot of res.uploads) {
      const file = files.find((f) => f.path === slot.path);
      if (!file) continue;
      try { await (deps.upload ?? uploadFile)(slot, file); uploaded.push(slot.artifactId); } catch (e) { c.warning((e as Error).message); }
    }
    if (uploaded.length) {
      const done = await completeReport(inputs.prodgatorUrl, 'github', res.reportId, uploaded, inputs.audience, client);
      for (const r of done.results.filter((r) => r.status !== 'uploaded')) c.warning(`artifact ${r.artifactId} was ${r.status}${r.reason ? `: ${r.reason}` : ''}`);
    }

    c.setOutput('report-id', res.reportId);
    c.setOutput('report-url', res.url);
    c.info(`Prodgator report: ${res.url}`);
  } catch (e) {
    let msg = e instanceof ReportError ? `${e.code}: ${e.message}` : (e as Error).message;
    if (/ACTIONS_ID_TOKEN_REQUEST_URL/.test(msg)) msg += ' Add `permissions: id-token: write` to the job or workflow.';
    if (failOnError) c.setFailed(`Prodgator report failed: ${msg}`);
    else c.warning(`Prodgator report was not sent: ${msg}`);
  } finally {
    await cleanup?.();
  }
}
