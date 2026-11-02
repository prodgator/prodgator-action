import { hashWorkspaceFile, type ArtifactFile, type AttestationInput } from '../../prodgator-report/src/core';

/** At most this many bytes: Prodgator refuses a larger ownership file. */
export const MAX_OWNERSHIP_BYTES = 256 * 1024;

/**
 * The `ownership` input: a CODEOWNERS file (or Prodgator ownership JSON) uploaded as an artifact of the report, with
 * an `ownership` attestation that points at it. Prodgator parses it; the action does not. The format is `json` for a
 * `.json` file, else `codeowners`. Read through safe-path: never from outside the workspace, through a symlink, or .git.
 */
export async function ownershipFile(file: string, workspace: string): Promise<{ attestation: AttestationInput | null; file: ArtifactFile | null; warning: string | null }> {
  const none = (warning: string) => ({ attestation: null, file: null, warning });
  const hashed = await hashWorkspaceFile(workspace, file);
  if (!hashed.ok) {
    if (hashed.reason === 'missing' || hashed.reason === 'not-file') return none(`${file} was not found (or is empty); no ownership report was sent`);
    return none(`${hashed.message}; no ownership report was sent`);
  }
  if (hashed.size === 0) return none(`${file} was not found (or is empty); no ownership report was sent`);
  if (hashed.size > MAX_OWNERSHIP_BYTES) return none(`${file} is larger than 256 KB; no ownership report was sent`);
  const { path, absolute } = hashed.file;
  const format = path.toLowerCase().endsWith('.json') ? 'json' : 'codeowners';
  return {
    // `ownership` is a kind of the Prodgator API that the shared report core does not list.
    attestation: { kind: 'ownership', name: 'codeowners', status: 'info', data: { format, artifact: path } } as unknown as AttestationInput,
    file: { path, absolute, workspace, size: hashed.size, sha256: hashed.sha256, contentType: format === 'json' ? 'application/json' : 'text/plain' },
    warning: null,
  };
}
