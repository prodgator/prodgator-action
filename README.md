# Prodgator report

Send a GitHub Actions job's summary, test results, coverage, SBOMs, scan results, custom evidence and artifacts to [Prodgator](https://app.prodgator.io). Authentication is GitHub OIDC: no API key or secret to create or rotate.

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

`permissions: id-token: write` lets the action mint a short-lived OIDC token; without it the step fails with a message telling you to add it. `if: always()` sends the report even when an earlier step in the job fails, so a broken build still shows its test results in Prodgator.

## If your workflow has approvals

Prodgator shows the summary and attestations on the run while a deployment waits for approval, and the AI release risk reads them, only if the report was sent before the approval. A job that uses an environment with required reviewers does not start until someone approves, so a report step inside it, or in a job that needs it, runs only after the approval. Send the report from the build or test job instead, or from a separate report job that needs the build and test jobs but not the deploy job:

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

      - uses: prodgator/prodgator-action@v1   # runs before the approval below
        if: always()
        with:
          junit: 'reports/**/*.xml'
          artifacts: 'dist/**'

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: production   # required reviewers: the job waits here
    steps:
      - run: ./deploy.sh
```

With several build and test jobs, add a `report` job with `needs: [build, test]` and `if: always()`, and have those jobs upload the files it reports as workflow artifacts. Do not make `report` depend on `deploy`. Without an environment that needs approval, a step at the end of the last job is the right place. The report cannot include results of jobs that run after the approval, such as the deployment itself.

## Inputs

| Name | Default | Description |
|---|---|---|
| `summary` | (none) | Markdown to send. Default: the summaries earlier steps of this job wrote to `$GITHUB_STEP_SUMMARY`. |
| `summary-file` | (none) | Path to a markdown file in the workspace to send instead (relative paths start at the workspace). |
| `name` | `default` | Report name within the job. Give each step a different name to send several reports from one job. |
| `job-name` | `$GITHUB_JOB` | Job identifier. |
| `matrix` | (none) | In matrix jobs, pass `${{ toJSON(matrix) }}` so each leg keeps its own report. |
| `junit` | (none) | Globs of JUnit XML files, summed into one `test-results` attestation. |
| `artifacts` | (none) | Globs of files to upload (newline or comma separated). |
| `attestations` | (none) | Attestations as inline JSON or a path to a JSON file. See Attestation kinds below. |
| `ownership` | (none) | Path of a `CODEOWNERS` file or a Prodgator ownership JSON file, sent for code owners rules on pull requests. See Ownership reports below. |
| `prodgator-url` | `https://api.prodgator.io` | Prodgator API URL. Point this at `https://api.prodgator.dev` or a self-hosted deployment. |
| `audience` | the origin of the URL in use | OIDC audience. Only set this if you know you need something other than the API origin. |
| `fail-on-error` | `false` | Fail the step when the report cannot be sent, instead of warning and continuing. |

This action is one of three ways to send a Prodgator run report: the [GitLab CI/CD component](https://gitlab.com/prodgator/prodgator-component) for GitLab CI, and the [Bitbucket Pipe](https://bitbucket.org/prodgator/prodgator-pipe) for Bitbucket Pipelines, cover the other two CI systems with the same report.

## Outputs

| Name | Description |
|---|---|
| `report-id` | The Prodgator report id. |
| `report-url` | Link to the pipeline run in Prodgator. |

## Attestation kinds

Pass one attestation or an array, inline as JSON or as a path to a JSON file:

```yaml
with:
  attestations: |
    [
      { "kind": "coverage", "name": "unit", "data": { "lines": 87.4, "threshold": 80 } }
    ]
```

Status (`pass`, `fail`, `warn`, `info`) is derived by Prodgator from the data for every kind except `custom`, which sets its own.

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

Prodgator reads findings from SARIF 2.1.0, CycloneDX JSON and SPDX JSON files. Run your scanner with SARIF output (for example `grype -o sarif` or `trivy --format sarif`) and use `"format": "sarif"`. `grype-json` and `trivy-json` are still accepted, but those files are only attached to the report: Prodgator reads no findings from them. See [Set up a scanner](https://docs.prodgator.io/security/uploads/scanners) for examples with ASH, Grype, Trivy, Semgrep, Checkov and Syft.

**custom** (status is required, since Prodgator has no rule for it):

```json
{ "kind": "custom", "name": "change-ticket", "status": "warn", "data": { "title": "Change ticket", "details": { "id": "CHG-1042" } } }
```

## Ownership reports

Code owners rules on pull requests need to know who owns each file. Send your `CODEOWNERS` file from a workflow that runs on pushes to your base branches:

```yaml
on:
  push:
    branches: [main]
jobs:
  ownership:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: prodgator/prodgator-action@v1
        with:
          ownership: .github/CODEOWNERS
```

The action uploads the file with the report and adds an `ownership` attestation that points at it. Prodgator reads the file (at most 256 KB and 5,000 rules) and uses it for pull requests into that branch. Owners are `@user` or `@org/team`; email owners are skipped. A file ending in `.json` is read as Prodgator ownership JSON:

```json
{ "version": 1, "rules": [{ "pattern": "infra/**", "owners": ["@acme/platform"] }] }
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

Without it, two legs of the same job reporting under the same `name` replace each other and Prodgator warns in the step log. With it, each leg keeps its own report.

## Limits

Prodgator enforces these regardless of what the action sends:

- 1 MiB per job summary
- 20 attestations per report
- 50 artifacts per report
- Per-plan caps on the largest single artifact file, artifact bytes per pipeline run, and artifact and summary bytes per organization per month
- 300 report requests per minute per organization

An upload that would cross a limit is skipped with a warning in the step log; the rest of the report still sends.

## Security

- OIDC only. No API key, no secret, nothing to rotate.
- The repository must belong to a GitHub organization or user connected to exactly one Prodgator organization through the Prodgator GitHub App. A repository under an unlinked owner logs a warning (`REPO_NOT_LINKED`) and the job still succeeds.
- Reports from `pull_request_target` and `workflow_run` events, and from a `pull_request` whose head repository is a fork, are accepted but marked **untrusted**. Release policies count only trusted attestations by default.
- Prodgator members download report artifacts only when signed in to the linked Prodgator organization.
- The action reads and uploads only files inside the workspace: the summary file, the attestations file, JUnit files, scanner files, the ownership file and artifacts. A file whose real path is outside the workspace (a symlink, or a file under a symlinked directory) is skipped with a warning, and nothing under a `.git` directory is read (`actions/checkout` stores the job token in `.git/config`). A skipped attestations file stops the report like a missing one. A step summary file that is a symlink is skipped too.

## How summaries are collected

When you don't pass `summary` or `summary-file`, the action reads the sibling `step_summary_*-scrubbed` files the runner writes next to its own `$GITHUB_STEP_SUMMARY` for every step that ran earlier in the job, and combines them. These are the secret-masked copies GitHub shows on the run page; the raw files beside them are ignored, so each step's summary is sent once and with secrets masked. This relies on the runner's current file layout, not a published API (GitHub does not expose job summaries any other way), so a runner change could silently break it. If that happens, `summary-file` still works, and the step logs a debug line when no summary was found.

## Troubleshooting

- **`REPO_NOT_LINKED`**: the repository's owner is not connected to a Prodgator organization, or the installation belongs to a different one. Install and link the Prodgator GitHub App for this owner.
- **`RUN_NOT_FOUND`, then the action succeeds anyway**: Prodgator had not yet received this run's webhook when the report arrived. The action retries for about 90 seconds; if it still fails, the job step warns (or fails, with `fail-on-error: true`) but does not block the workflow.
- **"Add `permissions: id-token: write`..."**: the job or workflow is missing OIDC permissions. Add `permissions: id-token: write` at the job or workflow level.
- **GitHub Enterprise Server with a custom OIDC issuer**: not supported yet. The action expects `github.com`'s OIDC issuer.
