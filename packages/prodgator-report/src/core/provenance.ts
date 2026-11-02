import { readWorkspaceText } from './safe-path';

const MAX_BYTES = 1024 * 1024;
/** The largest Sigstore bundle sent for verification; the server refuses larger ones. Real bundles are 5 to 15 KiB. */
export const MAX_BUNDLE_BYTES = 64 * 1024;
/** Subjects one provenance may name; the server allows the same. */
export const MAX_SUBJECTS = 64;
const object = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
const bad = (message: string): never => { throw new Error(`provenance ${message}`); };

/**
 * The summary fields Prodgator displays. They are hints: when a Sigstore bundle is sent, the server verifies it and
 * replaces them with what the signed statement says. A `signed` flag is checked for type and never sent: only the
 * server's verification decides whether a provenance is signed.
 */
function summary(d: Record<string, any>): Record<string, unknown> {
  if (!['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'].includes(d.predicateType)) bad('predicateType must be SLSA v1 or v0.2');
  if (!Array.isArray(d.subjects) || d.subjects.length > MAX_SUBJECTS) bad(`subjects must be an array of at most ${MAX_SUBJECTS} entries`);
  const text = (v: unknown, field: string, max: number): string => {
    if (typeof v !== 'string' || !v.trim() || v.length > max) bad(`${field} must be text of at most ${max} characters`);
    return v as string;
  };
  const out: Record<string, unknown> = {
    predicateType: d.predicateType,
    subjects: d.subjects.map((s: any) => {
      if (!object(s) || typeof s.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(s.sha256)) bad('subject sha256 must be 64 hex characters');
      return { name: text(s.name, 'subject name', 200), sha256: s.sha256 };
    }),
  };
  for (const [key, max] of Object.entries({ sourceRepository: 2000, sourceCommit: 40, sourceRef: 1000, workflowPath: 1000, builderId: 2000, invocationId: 2000 })) {
    if (d[key] !== undefined && d[key] !== null) out[key] = text(d[key], key, max);
  }
  if (out.sourceCommit !== undefined && !/^[a-f0-9]{40}$/i.test(out.sourceCommit as string)) bad('sourceCommit must be 40 hex characters');
  if (d.signed !== undefined && typeof d.signed !== 'boolean') bad('signed must be a boolean');
  return out;
}

/** A Sigstore bundle (as actions/attest-build-provenance writes it), as opposed to a bare envelope or statement. */
const isSigstoreBundle = (d: unknown): d is Record<string, any> =>
  object(d) && typeof d.mediaType === 'string' && d.mediaType.startsWith('application/vnd.dev.sigstore.bundle') && object(d.dsseEnvelope) && object(d.verificationMaterial);

export async function provenanceData(data: Record<string, unknown>, workspace: string): Promise<Record<string, unknown>> {
  if (!('bundle' in data)) return summary(data);
  if (typeof data.bundle !== 'string' || !data.bundle.trim()) bad('bundle must name a workspace file');
  const read = await readWorkspaceText(workspace, data.bundle as string, { maxBytes: MAX_BYTES });
  if (!read.ok) throw new Error(`provenance bundle ${read.message}; it was not read`);
  if (read.text === null || Buffer.byteLength(read.text, 'utf8') > MAX_BYTES) bad('bundle exceeds 1 MiB');
  let document: any;
  try { document = JSON.parse(read.text as string); } catch { bad('bundle must be JSON'); }
  let statement = document;
  const envelope = object(document) ? document.dsseEnvelope ?? ('payload' in document ? document : undefined) : undefined;
  if (envelope !== undefined) {
    if (!object(envelope) || typeof envelope.payload !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.payload)) bad('bundle has an invalid DSSE payload');
    try { statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')); } catch { bad('DSSE payload must be a JSON statement'); }
  }
  if (!object(statement) || !['https://in-toto.io/Statement/v1', 'https://in-toto.io/Statement/v0.1'].includes(statement._type) || !Array.isArray(statement.subject) || !object(statement.predicate)) bad('bundle must contain an in-toto statement');
  // A Sigstore bundle goes to the server as it is, for signature verification. A bare envelope or statement carries
  // no signature material, so only the summary is sent and the server stores it as unverified.
  let bundle: Record<string, any> | undefined;
  if (isSigstoreBundle(document)) {
    if (Buffer.byteLength(JSON.stringify(document), 'utf8') > MAX_BUNDLE_BYTES) bad(`Sigstore bundle exceeds ${MAX_BUNDLE_BYTES / 1024} KiB, the most Prodgator verifies`);
    bundle = document;
  }
  const p = statement.predicate;
  const workflow = p.buildDefinition?.externalParameters?.workflow;
  const dependencies = p.buildDefinition?.resolvedDependencies ?? p.materials;
  const source = Array.isArray(dependencies) ? dependencies.find((d: any) => object(d) && typeof d.digest?.gitCommit === 'string') : undefined;
  const uri = typeof source?.uri === 'string' ? source.uri.replace(/^git\+/, '') : undefined;
  const refAt = uri?.lastIndexOf('@') ?? -1;
  const out = summary({
    predicateType: statement.predicateType,
    subjects: statement.subject.map((s: any) => ({ name: s?.name, sha256: s?.digest?.sha256 })),
    sourceRepository: workflow?.repository ?? (refAt > 0 ? uri!.slice(0, refAt) : uri),
    sourceCommit: source?.digest?.gitCommit,
    sourceRef: workflow?.ref ?? (refAt > 0 ? uri!.slice(refAt + 1) : undefined),
    workflowPath: workflow?.path,
    builderId: p.runDetails?.builder?.id ?? p.builder?.id,
    invocationId: p.runDetails?.metadata?.invocationId,
  });
  return bundle ? { ...out, bundle } : out;
}
