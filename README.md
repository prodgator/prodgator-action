# Spindle report

Send a GitHub Actions job's summary, test results, coverage, SBOMs, scan results, custom evidence and artifacts to [Spindle](https://spindle.scrthq.com). Authentication is GitHub OIDC: no API key or secret to create or rotate.

## Quick start

```yaml
permissions:
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
      - run: npm run build

      - uses: prodgator/prodgator-action@v1
        if: always()
        with:
          junit: 'reports/**/*.xml'
          artifacts: 'dist/**'
```

`permissions: id-token: write` lets the action mint a short-lived OIDC token; without it the step fails with a message telling you to add it. `if: always()` sends the report even when an earlier step in the job fails, so a broken build still shows its test results in Spindle.

## Inputs

| Name | Default | Description |
|---|---|---|
| `summary` | (none) | Markdown to send. Default: the summaries earlier steps of this job wrote to `$GITHUB_STEP_SUMMARY`. |
| `summary-file` | (none) | Path to a markdown file to send instead. |
| `name` | `default` | Report name within the job. Give each step a different name to send several reports from one job. |
| `job-name` | `$GITHUB_JOB` | Job identifier. |
| `matrix` | (none) | In matrix jobs, pass `${{ toJSON(matrix) }}` so each leg keeps its own report. |
| `junit` | (none) | Globs of JUnit XML files, summed into one `test-results` attestation. |
| `artifacts` | (none) | Globs of files to upload (newline or comma separated). |
| `attestations` | (none) | Attestations as inline JSON or a path to a JSON file. See Attestation kinds below. |
| `spindle-url` | `https://api.spindle.scrthq.com` | Spindle API URL. Point this at `https://api.spindle.dev.scrthq.com` or a self-hosted deployment. |
| `audience` | the origin of `spindle-url` | OIDC audience. Only set this if you know you need something other than the API origin. |
| `fail-on-error` | `false` | Fail the step when the report cannot be sent, instead of warning and continuing. |

## Outputs

| Name | Description |
|---|---|
| `report-id` | The Spindle report id. |
| `report-url` | Link to the pipeline run in Spindle. |

## Attestation kinds

Pass one attestation or an array, inline as JSON or as a path to a JSON file:

```yaml
with:
  attestations: |
    [
      { "kind": "coverage", "name": "unit", "data": { "lines": 87.4, "threshold": 80 } }
    ]
```

Status (`pass`, `fail`, `warn`, `info`) is derived by Spindle from the data for every kind except `custom`, which sets its own.

**test-results** (also produced automatically from `junit`):

```json
{ "kind": "test-results", "name": "unit", "data": { "passed": 412, "failed": 0, "skipped": 3, "errors": 0 } }
```

**coverage** (`pass` when `lines >= threshold`, `info` with no threshold):

```json
{ "kind": "coverage", "name": "unit", "data": { "lines": 87.4, "threshold": 80 } }
```

**sbom**:

```json
{ "kind": "sbom", "name": "sbom", "data": { "format": "cyclonedx", "components": 311 } }
```

**scan** (`fail` when a count at or above `failOn` is greater than zero; `failOn` defaults to `high`):

```json
{ "kind": "scan", "name": "trivy", "data": { "tool": "trivy", "critical": 0, "high": 1, "medium": 4, "low": 9, "failOn": "high" } }
```

**Attaching the scanner's own file**: a `scan` or `sbom` attestation can also name the file the scanner wrote, with `file` (a path in the workspace) and, for scans, `format` (`sarif`, `cyclonedx`, `spdx`, `grype-json`, `trivy-json` or `other`). The action uploads that file as an artifact of the same report and links it from the attestation, so reviewers can download the raw output. For a SARIF file with no counts given, the action counts results by severity itself:

```json
{ "kind": "scan", "name": "trivy", "file": "trivy-results.sarif", "format": "sarif", "data": { "tool": "trivy", "failOn": "high" } }
```

A missing or empty file, or one outside the workspace, is skipped with a warning and the attestation is sent without the link.

Spindle reads findings from SARIF 2.1.0, CycloneDX JSON and SPDX JSON files. Run your scanner with SARIF output (for example `grype -o sarif` or `trivy --format sarif`) and use `"format": "sarif"`. `grype-json` and `trivy-json` are still accepted, but those files are only attached to the report: Spindle reads no findings from them. See [Scanner Setup (SARIF)](https://docs.spindle.scrthq.com/guides/security-scanners) for examples with ASH, Grype, Trivy, Semgrep, Checkov and Syft.

**custom** (status is required, since Spindle has no rule for it):

```json
{ "kind": "custom", "name": "change-ticket", "status": "warn", "data": { "title": "Change ticket", "details": { "id": "CHG-1042" } } }
```

## Matrix jobs

A JavaScript action cannot read the workflow's `matrix` context, so pass it explicitly:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
steps:
  - uses: prodgator/prodgator-action@v1
    if: always()
    with:
      matrix: ${{ toJSON(matrix) }}
```

Without it, two legs of the same job reporting under the same `name` replace each other and Spindle warns in the step log. With it, each leg keeps its own report.

## Limits

Spindle enforces these regardless of what the action sends:

- 1 MiB per job summary
- 20 attestations per report
- 50 artifacts per report
- Per-plan caps on the largest single artifact file, artifact bytes per pipeline run, and artifact and summary bytes per organization per month
- 300 report requests per minute per organization

An upload that would cross a limit is skipped with a warning in the step log; the rest of the report still sends.

## Security

- OIDC only. No API key, no secret, nothing to rotate.
- The repository must belong to a GitHub organization or user connected to exactly one Spindle organization through the Spindle GitHub App. A repository under an unlinked owner logs a warning (`REPO_NOT_LINKED`) and the job still succeeds.
- Reports from `pull_request_target` and `workflow_run` events, and from a `pull_request` whose head repository is a fork, are accepted but marked **untrusted**. Release policies count only trusted attestations by default.
- Spindle members download report artifacts only when signed in to the linked Spindle organization.
- The action uploads only files inside the workspace. A matched symlink whose target is outside the workspace is skipped, and nothing under a `.git` directory is uploaded (`actions/checkout` stores the job token in `.git/config`).

## How summaries are collected

When you don't pass `summary` or `summary-file`, the action reads the sibling `step_summary_*` files the runner writes next to its own `$GITHUB_STEP_SUMMARY` for every step that ran earlier in the job, and combines them. This relies on the runner's current file layout, not a published API (GitHub does not expose job summaries any other way), so a runner change could silently break it. If that happens, `summary-file` still works, and the step logs a debug line when no summary was found.

## Troubleshooting

- **`REPO_NOT_LINKED`**: the repository's owner is not connected to a Spindle organization, or the installation belongs to a different one. Install and link the Spindle GitHub App for this owner.
- **`RUN_NOT_FOUND`, then the action succeeds anyway**: Spindle had not yet received this run's webhook when the report arrived. The action retries for about 90 seconds; if it still fails, the job step warns (or fails, with `fail-on-error: true`) but does not block the workflow.
- **"Add `permissions: id-token: write`..."**: the job or workflow is missing OIDC permissions. Add `permissions: id-token: write` at the job or workflow level.
- **GitHub Enterprise Server with a custom OIDC issuer**: not supported yet. The action expects `github.com`'s OIDC issuer.
