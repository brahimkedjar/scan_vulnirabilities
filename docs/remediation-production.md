# Production remediation capability

Phase 5C is complete as a verified manual remediation workflow. Automatic
workspace modification is unavailable in the packaged extension because the
current VS Code/Node runtime cannot prove an atomic identity-preserving,
byte-preserving compare-and-replace operation for target files.

## Current capability matrix

| Ecosystem / manager | Production capability |
|---|---|
| npm | PREVIEW-ONLY |
| Yarn | PREVIEW-ONLY |
| pnpm | PREVIEW-ONLY |
| Bun | PREVIEW-ONLY |
| Python requirements | PREVIEW-ONLY |
| Poetry | PREVIEW-ONLY |
| Pipenv | PREVIEW-ONLY |
| Maven | PREVIEW-ONLY |
| Gradle | PREVIEW-ONLY |
| Cargo | PREVIEW-ONLY |
| Go Modules | PREVIEW-ONLY |
| NuGet | PREVIEW-ONLY |
| Composer | PREVIEW-ONLY |

Unsupported or incomplete recommendations are shown as manual review. They do
not produce an automatic Apply action.

## Safety guarantee

The extension guarantees that packaged production remediation preview actions
do not modify workspace files. The Remediation view and details panel can show
the package, current version, target version, vulnerabilities, confidence,
affected files, SHA-256 hashes, and real unified diffs. The webview can request
only host-resolved actions by preview token and bounded file index; it cannot
send file paths, replacement bytes, or a remediation plan.

## Refusal conditions

Automatic Apply is refused when any of the following is true:

- the host file adapter cannot prove atomic identity-and-hash replacement;
- the workspace is untrusted or virtual;
- the recommendation is stale, ambiguous, transitive-only, or unsupported;
- the scan is incomplete, severity-filtered, or provider-unavailable;
- the target file is dirty, missing, read-only, non-regular, a link, or outside
  the owning workspace root;
- Git state is observed as modified, conflicted, untracked, or partially
  staged; or
- any approval, plan, file hash, dependency graph, or workspace generation no
  longer matches.

## Verified manual workflow

1. Run a scan.
2. Open the Remediation view or a vulnerability details panel.
3. Generate a preview.
4. Inspect the unified diff, file hashes, confidence, and warnings.
5. Use Copy Patch, Open File, or Open Diff to apply the change manually.
6. Run a fresh scan.

Only a fresh scan with complete coverage and no remaining targeted findings can
be treated as fixed evidence. Provider failure, timeout, incomplete coverage,
unresolved dependencies, or remaining targeted findings are reported as
provider-unavailable, incomplete, unknown, or still vulnerable.

## Rollback behavior

Packaged production preview-only remediation does not write files, so there is
no production rollback action. The transaction engine is tested with injected
atomic filesystem adapters. Those tests require exact original bytes, exact
hash verification, and refusal to overwrite external user edits during rollback.

## Limitations

No package manager, shell, project script, VS Code task, terminal, Git command,
or arbitrary project code is executed. Lockfile resolution is never invented.
A future automatic Apply implementation must provide a platform-qualified
atomic compare-and-replace primitive and pass the same adversarial test suite
before any ecosystem can move beyond PREVIEW-ONLY.
