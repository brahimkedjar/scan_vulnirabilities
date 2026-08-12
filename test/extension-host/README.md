# Phase 5B / Phase 5C-safety extension-host smoke harness

This harness launches the development extension in VS Code 1.132 with fresh
user-data and extensions directories and copied workspaces. It never opens or
modifies a real project. The normal mode intercepts `fetch`
inside the Extension Development Host and returns deterministic OSV-shaped test
responses; no vulnerability result is hard-coded into production code.

Run the isolated deterministic suite from the extension root:

```powershell
.\scripts\phase4-smoke.ps1
```

The default downloads the exact VS Code 1.132.0 archive through a temporary,
pinned `@vscode/test-electron` 3.1.0 installation. To use an already-installed
VS Code 1.132.x executable instead:

```powershell
.\scripts\phase4-smoke.ps1 -Runtime Installed
```

The tooling package and, when selected, the VS Code archive may require network
access. OSV access remains disabled unless both live-mode switches are present:

```powershell
.\scripts\phase4-smoke.ps1 -RealOsv -AllowRealOsvNetwork
```

Live mode forwards the disposable fixture queries to `https://api.osv.dev` and
asserts provider success plus the exact observed canonical identities. It does
not assume that any package version is vulnerable, because advisory data can
change. The fixture covers an npm workspace/monorepo, PyPI, Maven, crates.io,
Go, NuGet, Packagist, multi-root aggregation, an unresolved Python range, and
an unsupported `bun.lockb` extraction path. The npm root and child workspace
share one external package identity so provider-query deduplication is checked.

The deterministic suite runs three isolated contexts. The original eight-root
workspace retains its deliberate incomplete-coverage paths and proves that no
complete historical result is mislabeled as available. A fresh frontend-only
context produces a complete scan and proves that `Show Remediation` uses the
stored result without rescanning or contacting OSV. A third, writable,
single-project fixture contains a deliberately pre-existing exact npm target
artifact and exercises the production remediation boundary.

The contexts validate provider-exact remediation candidates, command
registration, deterministic local analysis, cached refreshes, Problems
diagnostics, vulnerability/remediation details, tree hierarchy, status text,
dashboard remediation coverage, and strict nonce-based CSP. The multi-root
context also checks superseding-scan cancellation and provider failure. Every
fixture file is byte-counted and SHA-256 hashed before and after the run, while
the PowerShell driver independently verifies the source fixture hash.

The remediation context proves that preview is read-only, deterministic, and
network-free; includes SHA-256 hashes and real bounded unified diffs; and is
honestly classified `PREVIEW-ONLY` when the production host cannot prove a
race-safe conditional atomic replacement. Direct, traversal-shaped, and replayed
apply requests are refused without prompting, rescanning, or changing a byte.
The complete-scan context also resolves the dedicated Remediation view and
checks its strict CSP, explicit production-refusal notice, and absence of
Approve/Apply controls when the host exposes no `SAFE` capability. Unit and
integration coverage separately exercise the exact approval binding and strict
state-transition model through an injected atomic adapter.
The harness intercepts extension-originated `child_process`, terminal, task,
and execution-command routes and fails if any is attempted. Transaction success,
validation failure, exact-byte rollback, rollback verification, cancellation,
hash mismatch, and concurrent-user-edit behavior are covered by injected
filesystem unit tests because packaged production apply is deliberately disabled
until its filesystem primitive can meet the same guarantees.

Every run uses a root named
`dva4-<random token>` directly under the operating-system
temporary directory. Cleanup requires an exact leaf name, parent directory,
matching marker file, and non-reparse-point root before recursive removal.
`-KeepArtifacts` retains that disposable root for debugging.

Limitations:

- The test API is intentionally available only in an Extension Development or
  Test Host, never in a production-installed extension.
- The harness validates rendered filter controls and CSP HTML, but it does not
  drive Chromium inside a webview to click each filter.
- `-Runtime Installed` can fail if the same stable VS Code installation already
  has a running instance; the downloaded runtime is the isolated default.
- The harness exercises the source extension via `--extensionDevelopmentPath`.
  When `-VsixPath` is supplied, the packaged smoke verifies isolated install,
  activation, version, and command registration against the multi-root
  workspace; the deterministic diff/refusal interaction remains a development
  host check because the read-only inspection API is intentionally absent in
  production. VSIX content inspection remains a separate packaging check.
