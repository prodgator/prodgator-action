export type MatrixValue = string | number | boolean | null;
export type GlobFn = (patterns: string[]) => Promise<string[]>;
export interface AttestationInput { kind: 'test-results' | 'coverage' | 'sbom' | 'scan' | 'custom' | 'provenance'; name: string; status?: 'pass' | 'fail' | 'warn' | 'info'; data: Record<string, unknown>;
  /** Where the attestation came from: a workspace-relative POSIX path (or a glob pattern as text), never absolute. */
  sourcePath?: string }
export interface ArtifactRequest { path: string; size: number; sha256: string; contentType: string }
export interface IngestRequest { version: 1; job: { name: string; matrix: Record<string, MatrixValue> | null; runner: string | null }; name: string; summary: string | null; attestations: AttestationInput[]; artifacts: ArtifactRequest[] }
export interface UploadSlot { artifactId: string; path: string; url: string; method: 'PUT'; headers: Record<string, string>; expiresAt: string }
export interface IngestResponse { reportId: string; runId: string; attempt: number; url: string; trusted: boolean; uploads: UploadSlot[]; skipped: Array<{ path: string; reason: string }>; warnings: string[] }
export interface CompleteResponse { reportId: string; results: Array<{ artifactId: string; status: string; reason?: string }> }
