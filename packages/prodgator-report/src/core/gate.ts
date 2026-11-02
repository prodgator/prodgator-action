import { postJson, ReportError, type ClientDeps } from './client';

/** What Prodgator says about a deployment gate (Bitbucket, or any CI through /v1/ci, which also says `expired`). */
export type GateDecision = 'pending' | 'approved' | 'rejected' | 'closed' | 'expired';
export interface GateView {
  gateId: string; deploymentId: string; environment: string; decision: GateDecision; status: string;
  decidedBy: string | null; note: string | null; url: string; pollAfterSeconds: number;
}
export interface OpenedGate extends GateView { pollToken: string; expiresAt: string }

/** Open the gate of the deployment step that holds the OIDC token (Bitbucket only). */
export const openGate = (baseUrl: string, audience: string, deps: ClientDeps) =>
  postJson<OpenedGate>(`${baseUrl}/api/ingest/bitbucket/gates`, {}, audience, deps);

/** Read the gate's decision with the poll token opening returned. Network errors and 429/5xx are retryable. */
export async function readGate(baseUrl: string, gate: Pick<OpenedGate, 'gateId' | 'pollToken'>, deps: Pick<ClientDeps, 'fetch' | 'userAgent'>): Promise<GateView> {
  let res: Response;
  try {
    res = await (deps.fetch ?? fetch)(`${baseUrl}/api/ingest/bitbucket/gates/${encodeURIComponent(gate.gateId)}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${gate.pollToken}`, 'user-agent': deps.userAgent ?? 'prodgator-report/1' },
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e) {
    throw new ReportError(0, 'NETWORK', (e as Error).message, true);
  }
  if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
    throw new ReportError(res.status, 'REDIRECT_REFUSED', 'Prodgator answered with a redirect; the token is never sent to a redirected address. Check prodgator-url.', false);
  }
  if (res.ok) return (await res.json()) as GateView;
  const payload = await res.json().catch(() => ({})) as { code?: string; error?: string };
  const retryable = res.status === 429 || res.status >= 500;
  throw new ReportError(res.status, payload.code ?? `HTTP_${res.status}`, payload.error ?? res.statusText, retryable);
}
