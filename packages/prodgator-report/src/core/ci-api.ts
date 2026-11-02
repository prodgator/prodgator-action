/**
 * Client for the public `/v1/ci` endpoints (any CI system). Bodies and answers use the v1 field names (snake_case),
 * exactly as `CiRunCreate`, `CiReportCreate` and the other schemas of the v1 OpenAPI spec define them.
 *
 * Every call sends the API key or OIDC token from `deps.getToken`, except `getCiGate`, which sends only the gate's poll token.
 * Errors arrive as the v1 envelope `{ error: { code, message } }` and become a `ReportError` with that code and message.
 */
import { ReportError, requestJson, type ClientDeps, type HttpMethod } from './client';

export type CiRunEvent = 'push' | 'pull_request' | 'tag' | 'schedule' | 'manual' | 'other';
export type CiRunStatus = 'queued' | 'in_progress' | 'success' | 'failure' | 'cancelled' | 'timed_out' | 'skipped';
export const CI_FINAL_STATUSES = ['success', 'failure', 'cancelled', 'timed_out', 'skipped'] as const;
export const CI_START_STATUSES = ['queued', 'in_progress'] as const;

export interface CiRunCreateBody {
  ci_system: string; ci_system_name?: string; external_run_id: string; attempt: number; repository: string; commit_sha: string;
  ref?: string | null; pipeline_name: string; url?: string | null; status?: 'queued' | 'in_progress'; started_at?: string;
  actor?: string | null; event?: CiRunEvent; timeout_minutes?: number;
}
export interface CiRunUpdateBody { attempt: number; status?: CiRunStatus; completed_at?: string | null; url?: string | null }
export interface CiRun {
  id: string; provider: string; ci_system: string; ci_system_name: string | null; external_run_id: string; attempt: number;
  repository: string; commit_sha: string; ref: string | null; pipeline_name: string; url: string | null; status: string;
  started_at: string | null; completed_at: string | null; actor: string | null; event: string; deadline_at: string | null;
  trust: string; app_url: string; created_at: string; updated_at: string;
}

export interface CiAttestationBody {
  kind: string; name: string; status?: 'pass' | 'fail' | 'warn' | 'info'; source_path?: string; data: Record<string, unknown>;
}
export interface CiArtifactBody { path: string; size: number; sha256: string; content_type: string }
export interface CiReportCreateBody {
  attempt: number;
  job: { name: string; matrix?: Record<string, string | number | boolean | null> | null; runner?: string | null };
  name: string; summary?: string | null; attestations: CiAttestationBody[]; artifacts: CiArtifactBody[];
}
export interface CiUploadSlot { artifact_id: string; path: string; url: string; method: 'PUT'; headers: Record<string, string>; expires_at: string }
export interface CiSkippedArtifact { path: string; reason: string }
export interface CiReport {
  report_id: string; run_id: string; attempt: number; url: string; trust: string;
  uploads: CiUploadSlot[]; skipped: CiSkippedArtifact[]; warnings: string[];
}
export interface CiAttestationResult { report_id: string; attestations: Array<{ id: string; kind: string; name: string; status: string }>; warnings: string[] }
export interface CiArtifactReservation { report_id: string; uploads: CiUploadSlot[]; skipped: CiSkippedArtifact[]; warnings: string[] }
export interface CiArtifactCompletion { report_id: string; results: Array<{ artifact_id: string; status: string; reason?: string | null }> }

export interface CiGateOpenBody { run_id: string; attempt: number; environment: string; gate_id?: string; job?: string }
export interface CiGate {
  gate_id: string; deployment_id: string; environment: string; gate: { id: string; name: string } | null;
  /** Deploy only on `approved`; anything else, an unknown value included, is not an approval. */
  decision: string; status: string; decided_by: string | null; note: string | null; url: string; poll_after_seconds: number;
}
export interface CiGateOpened extends CiGate { poll_token: string; expires_at: string }

const enc = encodeURIComponent;

async function call<T>(method: HttpMethod, url: string, body: unknown, deps: ClientDeps): Promise<T> {
  // The audience only matters to token minters that need one (the GitHub action); generic credentials are read from the environment.
  const answer = await requestJson<{ data?: T }>(method, url, body, '', deps);
  if (!answer || typeof answer !== 'object' || !answer.data || typeof answer.data !== 'object') {
    throw new ReportError(200, 'BAD_RESPONSE', 'Prodgator answered without data. Check prodgator-url.', false);
  }
  return answer.data;
}

/** Creates the run, or returns the stored one for the same CI system, run id and attempt (safe to call from every step). */
export const createCiRun = (baseUrl: string, body: CiRunCreateBody, deps: ClientDeps) =>
  call<CiRun>('POST', `${baseUrl}/v1/ci/runs`, body, deps);

export const updateCiRun = (baseUrl: string, runId: string, body: CiRunUpdateBody, deps: ClientDeps) =>
  call<CiRun>('PATCH', `${baseUrl}/v1/ci/runs/${enc(runId)}`, body, deps);

export const createCiReport = (baseUrl: string, runId: string, body: CiReportCreateBody, deps: ClientDeps) =>
  call<CiReport>('POST', `${baseUrl}/v1/ci/runs/${enc(runId)}/reports`, body, deps);

export const addCiAttestations = (baseUrl: string, runId: string, reportId: string, attestations: CiAttestationBody[], deps: ClientDeps) =>
  call<CiAttestationResult>('POST', `${baseUrl}/v1/ci/runs/${enc(runId)}/reports/${enc(reportId)}/attestations`, { attestations }, deps);

export const reserveCiArtifacts = (baseUrl: string, runId: string, reportId: string, artifacts: CiArtifactBody[], deps: ClientDeps) =>
  call<CiArtifactReservation>('POST', `${baseUrl}/v1/ci/runs/${enc(runId)}/reports/${enc(reportId)}/artifacts`, { artifacts }, deps);

export const completeCiArtifacts = (baseUrl: string, runId: string, reportId: string, artifactIds: string[], deps: ClientDeps) =>
  call<CiArtifactCompletion>('POST', `${baseUrl}/v1/ci/runs/${enc(runId)}/reports/${enc(reportId)}/artifacts/complete`, { artifact_ids: artifactIds }, deps);

/** Opens (or reopens) a gate request for the run's deployment to an environment. The answer carries the poll token. */
export const openCiGate = (baseUrl: string, body: CiGateOpenBody, deps: ClientDeps) =>
  call<CiGateOpened>('POST', `${baseUrl}/v1/ci/gates`, body, deps);

/**
 * Reads a gate's decision with its poll token (never the API key or OIDC token). One attempt by default: the caller's polling
 * loop decides when to try again; network errors, 429 and 5xx are retryable `ReportError`s carrying any Retry-After.
 */
export const getCiGate = (baseUrl: string, gate: Pick<CiGateOpened, 'gate_id' | 'poll_token'>, deps: Pick<ClientDeps, 'fetch' | 'sleep' | 'userAgent' | 'maxAttempts'>) =>
  call<CiGate>('GET', `${baseUrl}/v1/ci/gates/${enc(gate.gate_id)}`, undefined, {
    fetch: deps.fetch, sleep: deps.sleep, userAgent: deps.userAgent, maxAttempts: deps.maxAttempts ?? 1,
    fixedToken: true, getToken: async () => gate.poll_token,
  });
