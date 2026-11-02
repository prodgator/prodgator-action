export * from './types';                 // MatrixValue, AttestationInput, ArtifactRequest, IngestRequest, UploadSlot, IngestResponse, CompleteResponse
export { MAX_SUMMARY_BYTES, truncateUtf8 } from './text';
export { parseJUnitXml, junitAttestations, type JUnitTotals } from './junit';  // junitAttestations(patterns, { glob, workspace, warn, name? })
export { parseCobertura, parseLcov, parseCoverage, coverageAttestations, CoverageError, MAX_COVERAGE_FILE_BYTES, type CoverageTotals, type CoverageFormat } from './coverage';  // coverageAttestations(patterns, { glob, workspace, warn })
export { cleanSourcePath, MAX_SOURCE_PATH_LENGTH, type CleanSourcePath } from './source-path';
export { parseAttestationsInput, resolveAttestationFiles, sarifCounts, MAX_SARIF_BYTES, type ScanFileFormat } from './attestations';
export { collectArtifacts, contentTypeFor, MAX_ARTIFACT_FILES, type ArtifactFile } from './artifacts'; // collectArtifacts(patterns, workspace, { glob: GlobFn })
export { checkWorkspacePath, displayName, hashWorkspaceFile, openWorkspaceFile, readWorkspaceText, sha256Handle, type Refusal, type RefusalReason, type WorkspaceFile } from './safe-path';
export { buildBlameSidecar, normalizeSnippet, BLAME_SIDECAR_SUFFIX, type BlameSidecar, type BlameResult, type GitRunner } from './blame';
export { buildIngestRequest } from './request';   // buildIngestRequest({ job: { name, matrix, runner }, name, summary, attestations, files })
export { ReportError, postJson, requestJson, sendReport, completeReport, type AzureContext, type ClientDeps, type HttpMethod, type ReportProvider } from './client';
export * from './ci-api';   // createCiRun, updateCiRun, createCiReport, addCiAttestations, reserveCiArtifacts, completeCiArtifacts, openCiGate, getCiGate
export { uploadFile } from './upload';
export { openGate, readGate, type GateDecision, type GateView, type OpenedGate } from './gate';
