import type { ArtifactFile } from './artifacts';
import type { AttestationInput, IngestRequest, MatrixValue } from './types';

export function buildIngestRequest(p: {
  job: { name: string; matrix: Record<string, MatrixValue> | null; runner: string | null };
  name: string; summary: string | null; attestations: AttestationInput[]; files: ArtifactFile[];
}): IngestRequest {
  return {
    version: 1, job: p.job, name: p.name, summary: p.summary, attestations: p.attestations,
    artifacts: p.files.map(({ path, size, sha256, contentType }) => ({ path, size, sha256, contentType })),
  };
}
