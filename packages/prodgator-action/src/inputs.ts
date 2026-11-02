import * as core from '@actions/core';
import type { MatrixValue } from '../../prodgator-report/src/core';

export const DEFAULT_PRODGATOR_URL = 'https://api.prodgator.io';
export interface ActionInputs { summary: string | null; summaryFile: string | null; name: string; jobName: string; matrix: Record<string, MatrixValue> | null; junit: string[]; junitName: string | null; coverage: string[]; artifacts: string[]; attestations: string | null; ownership: string | null; prodgatorUrl: string; audience: string; failOnError: boolean; blame: boolean }

export const audienceFor = (prodgatorUrl: string) => new URL(prodgatorUrl).origin;
const list = (v: string) => v.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
const orNull = (v: string) => (v.trim() ? v : null);

function matrix(raw: string): Record<string, MatrixValue> | null {
  if (!raw.trim()) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error('matrix must be JSON, for example ${{ toJSON(matrix) }}'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const entries = Object.entries(parsed as Record<string, unknown>).map(([k, v]) =>
    [k, v === null || ['string', 'number', 'boolean'].includes(typeof v) ? (v as MatrixValue) : JSON.stringify(v)] as const);
  return entries.length ? Object.fromEntries(entries) : null;
}

export function readInputs(get: (name: string) => string = (n) => core.getInput(n), env: NodeJS.ProcessEnv = process.env): ActionInputs {
  const prodgatorUrl = (get('prodgator-url').trim() || DEFAULT_PRODGATOR_URL).replace(/\/+$/, '');
  const u = new URL(prodgatorUrl);
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new Error('prodgator-url must use https');
  const failRaw = get('fail-on-error').trim().toLowerCase();
  if (failRaw && failRaw !== 'true' && failRaw !== 'false') core.warning(`fail-on-error "${failRaw}" is not true or false; using false`);
  const blameRaw = get('blame').trim().toLowerCase();
  if (blameRaw && blameRaw !== 'true' && blameRaw !== 'false') core.warning(`blame "${blameRaw}" is not true or false; using true`);
  return {
    summary: orNull(get('summary')),
    summaryFile: orNull(get('summary-file')),
    name: get('name').trim() || 'default',
    jobName: get('job-name').trim() || env.GITHUB_JOB || 'job',
    matrix: matrix(get('matrix')),
    junit: list(get('junit')),
    junitName: get('junit-name').trim() || null,
    coverage: list(get('coverage')),
    artifacts: list(get('artifacts')),
    attestations: orNull(get('attestations')),
    ownership: get('ownership').trim() || null,
    prodgatorUrl,
    audience: get('audience').trim() || audienceFor(prodgatorUrl),
    failOnError: failRaw === 'true',
    blame: blameRaw !== 'false',
  };
}
