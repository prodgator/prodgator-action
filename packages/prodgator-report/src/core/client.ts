import type { CompleteResponse, IngestRequest, IngestResponse } from './types';

export class ReportError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly retryable: boolean, readonly retryAfterMs?: number) {
    super(message);
    this.name = 'ReportError';
  }
}

export interface ClientDeps {
  getToken: (audience: string) => Promise<string>;
  fetch?: typeof fetch; sleep?: (ms: number) => Promise<void>; maxAttempts?: number;
  /** Sent as user-agent; the action passes `prodgator-report-action/<version>`. */
  userAgent?: string;
  /** GitLab and Bitbucket tokens cannot be re-minted mid-job: an expired token is final. */
  fixedToken?: boolean;
}

/** Extra attempts, after the first six, while the answer is RUN_NOT_FOUND. */
const RUN_NOT_FOUND_EXTRA_ATTEMPTS = 2;
const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
/**
 * The longest Retry-After the client waits out. A longer one (the daily run cap answers with the time until the next UTC
 * day) would hold the CI job for hours, so the request fails at once instead.
 */
export const MAX_RETRY_AFTER_MS = 60_000;

function waitText(ms: number): string {
  const s = Math.ceil(ms / 1000);
  if (s >= 3600) { const h = Math.round(s / 3600); return `${h} hour${h === 1 ? '' : 's'}`; }
  if (s >= 60) { const m = Math.round(s / 60); return `${m} minute${m === 1 ? '' : 's'}`; }
  return `${s} seconds`;
}
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export type HttpMethod = 'GET' | 'POST' | 'PATCH';

/**
 * The code and message of an error answer: the ingest routes send `{ code, error, retryable }`, the public v1 API the
 * envelope `{ error: { code, message } }`.
 */
function errorFields(payload: { code?: unknown; error?: unknown; retryable?: unknown }): { code?: string; message?: string; retryable?: boolean } {
  const env = payload.error;
  if (env && typeof env === 'object') {
    const e = env as { code?: unknown; message?: unknown };
    return { code: typeof e.code === 'string' ? e.code : undefined, message: typeof e.message === 'string' ? e.message : undefined };
  }
  return {
    code: typeof payload.code === 'string' ? payload.code : undefined, message: typeof env === 'string' ? env : undefined,
    retryable: payload.retryable === true ? true : undefined,
  };
}

export const postJson = <T>(url: string, body: unknown, audience: string, deps: ClientDeps): Promise<T> => requestJson<T>('POST', url, body, audience, deps);

/**
 * Sends one JSON request with the bearer token, retrying network errors, 429 and 5xx (honouring a Retry-After of up to
 * MAX_RETRY_AFTER_MS; a longer one fails at once). Never follows a redirect.
 */
export async function requestJson<T>(method: HttpMethod, url: string, body: unknown, audience: string, deps: ClientDeps): Promise<T> {
  const doFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? wait;
  const max = deps.maxAttempts ?? 6;
  let last: ReportError | null = null;
  // A pipeline Prodgator has not recorded yet (RUN_NOT_FOUND) gets two more tries: about 90 s in all instead of 50 s.
  for (let attempt = 0; attempt < (last?.code === 'RUN_NOT_FOUND' && deps.maxAttempts === undefined ? max + RUN_NOT_FOUND_EXTRA_ATTEMPTS : max); attempt++) {
    if (attempt > 0) await sleep(last?.retryAfterMs ?? Math.min(20_000, 2000 * 2 ** (attempt - 1)));
    let res: Response;
    try {
      const token = await deps.getToken(audience);
      const headers: Record<string, string> = { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'user-agent': deps.userAgent ?? 'prodgator-report/1' };
      if (body === undefined) delete headers['content-type'];
      res = await doFetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        // A redirect would carry the token to another address: never follow one.
        redirect: 'manual',
        signal: AbortSignal.timeout(30_000),
      });
    } catch (e) {
      if (/ACTIONS_ID_TOKEN_REQUEST_URL|id-token/i.test((e as Error).message)) throw e;   // permission problem: no point retrying
      last = new ReportError(0, 'NETWORK', (e as Error).message, true);
      continue;
    }
    // res.clone() rather than res.json(): a real fetch() Response is always fresh per call, so
    // this is a no-op there, but it keeps a single Response instance re-readable when a test
    // stubs the same instance across several retry attempts (Response bodies are single-use).
    if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
      throw new ReportError(res.status, 'REDIRECT_REFUSED', 'Prodgator answered with a redirect; the token is never sent to a redirected address. Check prodgator-url.', false);
    }
    if (res.ok) return (await res.clone().json()) as T;
    const raw: unknown = await res.clone().json().catch(() => ({}));
    const payload = errorFields(raw && typeof raw === 'object' ? raw as Record<string, unknown> : {});
    const retryable = !(deps.fixedToken && payload.code === 'TOKEN_EXPIRED') && (payload.retryable === true || RETRY_STATUS.has(res.status));
    const retryAfter = Number(res.headers.get('retry-after'));
    const retryAfterMs = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : undefined;
    const code = payload.code ?? `HTTP_${res.status}`;
    const message = payload.message ?? res.statusText;
    if (retryable && retryAfterMs !== undefined && retryAfterMs > MAX_RETRY_AFTER_MS) {
      throw new ReportError(res.status, code,
        `${message} (Prodgator asked to wait ${waitText(retryAfterMs)} before trying again, longer than prodgator-report waits, so it stopped)`,
        false, retryAfterMs);
    }
    last = new ReportError(res.status, code, message, retryable, retryAfterMs);
    if (!retryable) throw last;
  }
  throw last!;
}

export type ReportProvider = 'github' | 'gitlab' | 'bitbucket' | 'azure';
/** What an Azure Pipelines job says about itself; the server checks it against Azure DevOps. */
export interface AzureContext { collectionUri: string; projectId: string; buildId: number; jobId: string; attempt: number; sha: string }
export const sendReport = (baseUrl: string, provider: ReportProvider, req: IngestRequest, audience: string, deps: ClientDeps, azure?: AzureContext) =>
  postJson<IngestResponse>(`${baseUrl}/api/ingest/${provider}/reports`, azure ? { ...req, azure } : req, audience, deps);
export const completeReport = (baseUrl: string, provider: ReportProvider, reportId: string, artifactIds: string[], audience: string, deps: ClientDeps, azure?: AzureContext) =>
  postJson<CompleteResponse>(`${baseUrl}/api/ingest/${provider}/reports/${encodeURIComponent(reportId)}/complete`, azure ? { artifactIds, azure } : { artifactIds }, audience, deps);
