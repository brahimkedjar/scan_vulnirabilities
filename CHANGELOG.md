# Changelog

## 0.9.0 - 2026-08-13

- Add a host-neutral, injected filesystem/network/clock/cancellation/logging
  core boundary and a bundled `dependency-auditor` headless entry point.
- Add production CLI `scan` and `gate` workflows across the existing thirteen
  static package-manager adapters and seven canonical OSV ecosystems. Exit
  codes distinguish pass, policy violation, incomplete/unknown evidence,
  invalid configuration, and internal failure.
- Add bounded CLI output in text, JSON, SARIF 2.1.0, CycloneDX JSON 1.6,
  self-contained script-free HTML, Markdown, and formula-neutralized CSV.
  Output files are exclusively created and never overwritten.
- Add tested host-neutral engines for explicit-metadata license inventory,
  provenance and evidence-supported anomaly classification, JS/TS/Python
  static reachability, cross-project version drift, CycloneDX JSON 1.4-1.6
  import/diff/merge, immutable security snapshots and baselines, historical
  security diff, advanced evidence policy, and local uncompressed Docker/OCI
  archive inventory.
- Keep integration states explicit: the CLI gate joins KEV, license,
  provenance, reachability, and diff evidence into reports when the evidence
  is generated, and license, provenance, reachability, and container commands
  return the incomplete exit code instead of reporting success when evidence
  remains unknown. VS Code scans do not automatically run the Phase 8 evidence
  engines.
- Add fail-closed CI examples for GitHub Actions, GitLab CI, Azure Pipelines,
  Jenkins, and generic POSIX shell runners. Templates require a pre-provisioned,
  version-pinned CLI and never install or execute a package manager.
- Expand the VS Code dashboard with evidence-bound platform dimensions. An
  unknown or not-configured dimension is never presented as clean, compliant,
  trusted, or unreachable.
- Preserve the static execution boundary: no package manager, build tool,
  project code, lifecycle script, Git command, container daemon, image pull, or
  container execution is introduced.
- Document explicit Phase 8 non-capabilities: no CycloneDX XML, no SPDX, no
  direct registry/container-image access, no CLI persistent cache, no usable
  local vulnerability database ingestion, and no production remediation Apply.

## 0.8.0 - 2026-08-12

- Add the first production Phase 7 supply-chain intelligence slice. This is not
  completion of the broader Phase 7 roadmap.
- Preserve the unfiltered normalized OSV finding set alongside severity-filtered
  presentation findings so policy and exports cannot be bypassed by a UI filter.
- Add a bounded provider-neutral evidence model that retains source
  observations, field-level evidence, aliases, freshness, conflicts,
  confidence reasons, and missing fields without merging different package
  coordinates. The runtime still performs package vulnerability lookup through
  OSV only; no direct NVD or GHSA query is claimed.
- Add CISA Known Exploited Vulnerabilities catalog enrichment using a fixed
  HTTPS feed, strict catalog validation, isolated caching, exact CVE matching,
  and fail-closed `UNKNOWN` results when the catalog or identity is not fresh
  and usable. No workspace or package data is sent to CISA.
- Add deterministic per-finding risk bounds from normalized severity, CVSS,
  CISA KEV evidence, and reachability evidence. Missing evidence contributes no
  invented points and remains visible in the maximum score; reachability is
  currently `UNKNOWN` because this release has no reachability engine.
- Add a bounded local security-policy evaluator for severity/CVSS thresholds
  and counts, known-exploitation absence, ecosystem/package allow and block
  rules, and expiring advisory ignores. Invalid policy, incomplete latest-attempt
  coverage, hidden findings, cancellation, and required unknown evidence fail
  closed.
- Add deterministic CycloneDX JSON 1.6 generation with canonical purls,
  occurrence evidence, proven relationships, OSV vulnerabilities, and explicit
  inventory/vulnerability completeness compositions.
- Add deterministic SARIF 2.1.0 generation with safe workspace-relative
  locations, stable partial fingerprints, unfiltered findings, and invocation
  warnings for omitted locations or incomplete source coverage.
- Keep package-manager and project-code execution prohibited. This release does
  not add a headless scanner CLI, CycloneDX XML, SPDX, SBOM import/diff,
  license/container/provenance/health analysis, or source-code reachability.

## 0.7.0 - 2026-08-12

- Add an explicit, bounded remediation state machine and exact-proposal
  approval records. Preview, approval, final Apply confirmation, validation,
  verification, failure, rollback, stale, unsupported, manual-action,
  manual-review, and post-scan result states cannot be skipped or replayed.
- Add a dedicated Remediation view with current findings, evidence, real
  bounded diffs, advisory Git state, state-gated actions, and explicit
  preview-only manual actions for opening diffs, copying patches, opening
  affected files, and rescanning.
- Harden file reads against final-leaf links/reparse points, growth, and
  identity changes, and add immutable post-apply classification models plus
  exact rollback-on-still-vulnerable verification tests.
- Keep production Apply disabled for every ecosystem. The current public
  Node/VS Code filesystem APIs cannot atomically compare a target's identity
  and exact bytes as part of replacement, so the Phase 5C production-mutation
  guarantee is not proven. Phase 5C completes as a verified manual remediation
  workflow with explicit preview, manual patch, and fresh-scan verification.

## 0.6.0 - 2026-08-12

- Add an explicit review, preview, approval, transaction, validation, rescan,
  and rollback workflow for conservative dependency remediation.
- Add narrowly bounded npm direct-dependency fix previews when an exact
  package-lock v3 resolution is already present and can be reused without
  inventing registry, integrity, or graph metadata. Keep packaged workspace
  apply disabled until the host can prove race-safe conditional atomic replace.
- Preserve exact original bytes for rollback, revalidate preview hashes and
  recommendation state before writes, reject dirty/read-only/non-regular files,
  and confine every target to a trusted local workspace.
- Add native read-only diffs, session-only remediation history, and actual
  before/after scan comparisons without persisting file snapshots or secrets.
- Keep Yarn, pnpm, Bun, Python, Poetry, Pipenv, Maven, Gradle, Cargo, Go, NuGet,
  and Composer remediation preview-only or unsupported when safe lockfile
  resolution cannot be proven locally.
- Continue to prohibit package-manager, shell, project-script, Git, CI/CD,
  SARIF, CLI, and scheduled remediation execution.

## 0.5.0 - 2026-08-12

- Add deterministic, local Remediation Intelligence derived exclusively from
  stored scan results and normalized provider fixed-version events.
- Aggregate multiple advisories per exact dependency occurrence, select
  conservative ecosystem-aware candidates, and surface conflicts, unresolved
  identities, and advisories without a known fix as explicit manual-review
  outcomes.
- Distinguish direct upgrades from transitive parent review without inventing a
  future parent version; preserve the authoritative dependency path, evidence,
  confidence, and non-authoritative compatibility-risk heuristic.
- Add remediation summaries to Details, Dashboard, Tree, Problems, and Status,
  plus the read-only `Dependency Auditor: Show Remediation` command.
- Keep Phase 5A analysis-only: no workspace writes, package-manager/build-tool
  execution, provider request, or automatic fix is introduced.

## 0.4.0 - 2026-08-12

- Add a common static package-manager adapter contract and bounded workspace
  orchestration with per-project provenance for multi-root workspaces and
  monorepos. A global scheduler runs at most four project scans across all
  workspace folders, shares a 256 MiB metadata-read budget, and retains at most
  10,000 dependency records per scan.
- Add tested adapters for Yarn, pnpm, Bun text locks, Python requirements,
  Poetry, Pipenv, Maven, Gradle, Cargo, Go Modules, NuGet, and Composer while
  preserving npm package-lock and shrinkwrap support.
- Add canonical OSV mapping for npm, PyPI, Maven, crates.io, Go, NuGet, and
  Packagist, including ecosystem-specific package identity validation and PyPI
  name normalization.
- Generalize the shared OSV audit, normalization, deduplication, and cache
  pipeline across ecosystems. Cache subjects are isolated by provider,
  ecosystem, canonical package name, and exact version.
- Add per-project and per-ecosystem discovered, resolved, checked, vulnerable,
  unresolved, and unsupported coverage. Partial, unavailable, and stale-fallback
  outcomes cannot be presented as a clean scan.
- Add workspace/ecosystem Tree View grouping, ecosystem Dashboard filters and
  coverage, ecosystem-aware details and diagnostics, and unresolved counts in
  aggregate status.
- Preserve non-reconfirmed findings from the last complete scan as a separate,
  bounded, visibly historical evidence set when a later attempt is partial,
  without inflating current coverage, provider, dependency, or risk totals.
- Add the `dependencyAuditor.enabledEcosystems` setting with all canonical
  supported OSV ecosystems enabled by default.
- Keep dependency discovery static and read-only: package managers, build tools,
  project code, lifecycle scripts, restores, and lockfile generation are never
  executed. Binary `bun.lockb` files are detected and reported as an explicit
  coverage gap.
- Gate npm-family identities against bounded workspace-local `.npmrc`,
  `.yarnrc`, and `.yarnrc.yml` registry settings, plus Bun's workspace-local
  `bunfig.toml`. Custom, interpolated, ambiguous, or unreadable sources remain
  unsupported and are never submitted; user and global package-manager
  configuration is intentionally not read.
- Inspect workspace-local Maven POM and `.mvn` configuration/extensions,
  Gradle build/settings/plugins, and NuGet `NuGet.Config` plus implicit
  `Directory.Build` props/targets source declarations. External user/machine
  source configuration remains unobservable and selected executable, external,
  or ambiguous sources fail closed.
- Reconcile statically checkable manifest constraints, lock selections, and
  reachable graph edges. Missing, incompatible, or stale/mismatched selections
  remain explicit coverage gaps instead of guessed exact versions.
- Add bounded deterministic fixtures and parser/provider regression coverage for
  the new ecosystems, malformed metadata, unresolved versions, unsafe sources,
  workspaces, and cancellation.

## 0.3.0 - 2026-08-11

- Add the Dependency Security Tree View, dashboard, vulnerability details, and
  status-bar integration backed by the shared scan-result store.
- Add safe HTTPS advisory actions and strict, provider-data-safe Webview
  rendering with a restrictive Content Security Policy.
- Add deterministic dependency risk scoring, coverage/error states, rescan and
  explicit vulnerability-database refresh actions.
- Add transitive dependency diagnostics on the nearest declared introducer.
- Add startup/change scan controls, dependency-scope and minimum-severity
  settings, UI security tests, and extension-host UI verification.

## 0.2.0 - 2026-08-11

- Add authoritative npm package-lock v2/v3 dependency graph parsing.
- Add configured npm workspace origins, alias manifest keys, and registry-source
  provenance checks.
- Add cache-aware OSV queries with bounded HTTPS networking and cancellation.
- Normalize advisories, npm semantic-version ranges, fixed versions, aliases,
  references, CVSS severity, and provider severity.
- Add coverage-aware Output Channel reports and direct-dependency diagnostics.
- Add deterministic mocked provider, cache, network, graph, and security tests.
- Add scan-wide/cache-wide resource budgets and coverage-aware limit reporting.

## 0.1.0 - 2026-08-11

- Add the Phase 1 VS Code extension scaffold.
- Add read-only, multi-root dependency-file discovery.
- Detect supported package-manager candidates without executing workspace code.
- Add structured Output Channel logging and offline unit tests.
