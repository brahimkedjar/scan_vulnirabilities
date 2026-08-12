# Architecture

Dependency Vulnerability Auditor separates local dependency discovery from
remote vulnerability analysis. Package-manager adapters know how to read
dependency metadata; they do not know how to contact OSV. The vulnerability
pipeline accepts one ecosystem-independent dependency model and is reused by
every adapter.

## Data flow

```text
VS Code workspace folders
        |
        v
Package-manager detection
        |
        v
Static adapters and parsers
        |
        v
Unified Dependency records
        |
        v
Canonical ecosystem/identity mapper
        |
        v
Cache-aware VulnerabilityProvider (OSV)
        |
        v
Normalized Vulnerability records
        |
        v
Coverage-aware ScanResult store
        |
        v
Local RemediationAnalyzer
        |
        +--> Tree View
        +--> Dashboard and Details
        +--> Problems diagnostics
        +--> Status Bar and Output Channel
```

The scan-result store is the UI source of truth. `RemediationAnalyzer` is a
deterministic, bounded, synchronous analysis layer over those immutable results;
it neither parses OSV again nor performs I/O. Opening or filtering a view does
not start a provider query. A query occurs only through the normal scan command,
an enabled automatic scan trigger, or an explicit vulnerability-database
refresh.

## Package-manager adapter boundary

`src/package-managers/PackageManagerAdapter.ts` defines the common contract:

```ts
interface PackageManagerAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly ecosystems: readonly string[];

  detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult>;

  scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions & {
      preDetectedResult?: DetectionResult;
      targetProject?: DetectedDependencyProject;
    },
    signal?: AbortSignal,
  ): Promise<DependencyScanResult>;
}
```

An adapter is responsible for:

1. discovering only its supported manifests and resolution files;
2. grouping those files into independent dependency projects;
3. parsing bounded, untrusted metadata;
4. determining whether a version is resolved, unresolved, or unsupported;
5. classifying direct/transitive and production/development/optional/peer
   dependencies where the source format proves that classification;
6. constructing safe relationship paths where the source format preserves
   enough graph information; and
7. reporting project coverage and explicit parsing/coverage errors.

An adapter must not call OSV, run a package manager, evaluate a build file,
execute project code, generate a lockfile, or modify dependency metadata.

`WorkspaceDependencyScanner` is the adapter registry and orchestrator. It
filters adapters by `dependencyAuditor.enabledEcosystems`, detects each adapter
once per workspace folder, and passes the complete immutable detection result
plus one selected project into each bounded work unit. One global scheduler runs
at most four project scans across every adapter and every folder in a multi-root
workspace. Keeping the complete detection context preserves nested-lock and
workspace ownership without rescanning sibling projects. Failures from one work
unit become structured workspace errors rather than erasing other results.
Cancellation is propagated through adapters and parsers.

### Implemented adapters

| Adapter | Static inputs | Canonical ecosystem | Important boundary |
|---|---|---|---|
| npm | `package.json`, `package-lock.json` / `npm-shrinkwrap.json` v2/v3 | `npm` | Only safely identified registry releases are provider subjects |
| Yarn | `package.json`, Classic/Berry `yarn.lock` | `npm` | Unknown Berry metadata and non-registry protocols are coverage gaps |
| pnpm | `package.json`, `pnpm-lock.yaml` v5/v6/v9 | `npm` | Workspace/local references are not external npm versions |
| Bun | `package.json`, text `bun.lock` v0-v2 | `npm` | `bun.lockb` is detected but not parsed or converted |
| Python requirements | Common requirements text files | `PyPI` | Only exact `==` pins are resolved query subjects |
| Poetry | `pyproject.toml`, `poetry.lock` | `PyPI` | Lock entries are authoritative |
| Pipenv | `Pipfile`, `Pipfile.lock` | `PyPI` | Lock entries are authoritative |
| Maven | `pom.xml` | `Maven` | Safe direct coordinates only; no resolved transitive graph |
| Gradle | `build.gradle` / `build.gradle.kts`, `gradle.lockfile` | `Maven` | Literal direct selections are reconciled; graphless unmatched lock entries remain unresolved |
| Cargo | `Cargo.toml`, `Cargo.lock` v1-v4 | `crates.io` | Local/Git/custom-registry roots are not crates.io identities |
| Go Modules | `go.mod`, `go.sum` | `Go` | Queryable versions require Go 1.17+ graph metadata plus a matching checksum |
| NuGet | `*.csproj`, `packages.config`, lock JSON v1-v3 | `NuGet` | Lock targets provide graph data; `packages.config` is flat |
| Composer | `composer.json`, `composer.lock` | `Packagist` | Custom/path repository provenance is not assumed to be Packagist |

The table describes the static subset intentionally supported by each parser.
Missing locks, unsupported format versions, dynamic declarations, ambiguous
edges, and parser safety limits remain visible as gaps.

### Source-provenance boundary

Public-registry identity is accepted only when the bounded workspace metadata
that the extension can observe supports it:

- npm-family adapters inspect workspace-local `.npmrc`, `.yarnrc`,
  `.yarnrc.yml`, and `bunfig.toml` registry settings;
- Maven inspects applicable workspace POM repository/build-extension
  declarations plus `.mvn/{maven,jvm}.config` and `.mvn/extensions.xml`;
  selected settings, alternate POMs, local/offline repositories, and executable
  extensions fail closed;
- Gradle inspects repository declarations in applicable workspace build and
  settings scripts without evaluating them; and
- NuGet inspects applicable workspace `NuGet.Config`, project `RestoreSources`,
  and ancestor `Directory.Build.props` / `Directory.Build.targets`
  restore-source declarations.

User- and machine-level package-manager configuration, external Maven settings,
Gradle init/user configuration, and NuGet configuration outside the workspace
are not observable. An explicit custom, interpolated, ambiguous, selected
external, unreadable, or discovery-truncated source therefore produces
unsupported coverage rather than an assumed public-registry identity.

## Unified dependency model

Every adapter produces `Dependency` records with the same core fields:

- canonical package `name` and `ecosystem`;
- exact `installedVersion` when proven and the original
  `requestedVersion` where available;
- `resolutionStatus`: `resolved`, `unresolved`, or `unsupported`;
- `dependencyType` and `environment`;
- optional `parent` and `dependencyPath`;
- `manifestPath`, `lockfilePath`, `packageManager`, `projectPath`, and
  `workspacePath` provenance; and
- bounded optional `metadata` for source details that do not belong in the
  common model.

An unresolved or unsupported record has no installed version and cannot reach a
vulnerability provider. A requested range is not promoted to an installed
version. The optional metadata object carries facts such as a source line,
configuration name, checksum presence, or manifest section; vulnerability logic
does not depend on manager-specific object shapes.

Parsers reconcile manifest constraints, lock selections, and reachable graph
edges wherever the static formats expose enough information. A missing,
incompatible, unreachable, or stale/mismatched selection remains unresolved.
This detects statically demonstrable freshness failures; it does not claim to
recognize every stale lockfile state without executing a package manager.

## Ecosystem mapping and canonical identity

`src/vulnerability/EcosystemMapper.ts` is the only adapter-to-OSV mapping
boundary. It accepts aliases from internal adapter identifiers but emits one of
the exact, case-sensitive OSV ecosystem values:

| Adapter family | OSV ecosystem | Identity retained |
|---|---|---|
| npm, Yarn, pnpm, Bun | `npm` | npm package name, including scope |
| requirements, Poetry, Pipenv | `PyPI` | PEP 503-normalized project name |
| Maven, Gradle | `Maven` | `groupId:artifactId` |
| Cargo | `crates.io` | crate name |
| Go Modules | `Go` | full module path |
| NuGet | `NuGet` | package ID |
| Composer | `Packagist` | `vendor/package` |

The mapper validates bounds, control characters, ecosystem-specific package
syntax, and exact version tokens. npm versions additionally require strict
semantic-version validity. It does not shorten compound identities: Maven
`groupId:artifactId`, full Go module paths, scoped npm names, and Composer
`vendor/package` names are preserved.

If mapping is not exact and safe, the dependency is classified as unresolved or
unsupported and no request is made. This prevents a local path, alias source,
dynamic version, malformed package name, or ambiguous replacement from being
queried as an unrelated public package.

## Why providers are separate from adapters

The adapter/provider split has four security and maintenance benefits:

- Package formats can evolve without duplicating network, cache, retry,
  cancellation, deduplication, severity, or UI logic.
- A provider never parses workspace files and an adapter never handles remote
  advisory data, keeping both trust boundaries small.
- All ecosystems receive the same request limits, failure semantics, normalized
  vulnerability model, and output handling.
- A future provider can implement `VulnerabilityProvider` without adding a
  second set of package-manager scanners.

There is one OSV pipeline, not an npm scanner, a Python vulnerability scanner,
and a Maven vulnerability scanner.

## Vulnerability audit pipeline

`DependencyAuditService` maps each resolved dependency to an OSV subject and
deduplicates by:

```text
canonical ecosystem + canonical package name + exact version
```

At most 5,000 unique subjects enter one audit and at most five provider requests
run concurrently. A duplicate subject in multiple projects reuses the same
provider result, while its project and manifest provenance remains in the
dependency and coverage records.

For each subject, the service:

1. validates the canonical identity;
2. checks a fresh cache entry;
3. queries the provider if needed;
4. validates and normalizes untrusted provider data;
5. uses an expired successful value only as an explicitly counted stale
   fallback when a live query fails; and
6. writes only successful provider outcomes after the scan completes.

`OsvProvider` sends the minimal exact package/version query to the allowlisted
HTTPS endpoint and applies bounded pagination. `VulnerabilityNormalizer`
converts OSV records to the shared `Vulnerability` model, validates advisory
references and timestamps, normalizes severity, and avoids inventing remediation
data. npm range handling uses strict semantic version rules. Other ecosystems
use OSV's exact-version response rather than guessing ecosystem-specific version
ordering locally.

## Cache isolation

`VulnerabilityCache` stores successful results in VS Code `globalState` under
a validated tuple:

```text
[provider, ecosystem, canonicalPackageName, exactVersion]
```

Including the ecosystem prevents equal-looking names in two registries from
sharing results. Including the version prevents a result for one release from
satisfying another. Provider/network errors are never cached as successful
empty results. Cache entries and the total cache have byte/count limits and a
time-to-live. Refresh clears the cache before running the same audit pipeline.

## Project and workspace boundaries

The command enumerates every VS Code workspace folder. An adapter groups
manifest and lock files by the independently detected project root, and records
both `workspacePath` and `projectPath`. Project coverage also retains the
contributing manifest paths and package-manager IDs. Detection is performed per
folder, then project work from all folders enters one deterministic global queue
with a maximum of four active project scans.

Workspace-aware npm, Yarn, pnpm, Bun, and Cargo parsing follows only statically
validated local workspace metadata. It does not treat every nested manifest as a
workspace member. Unrelated projects retain separate graphs even when their
provider subjects happen to deduplicate.

## Coverage model

`ScanResult` holds both `projectCoverage` and ecosystem-aggregated
`ecosystemCoverage`. Each row contains:

| Field | Meaning |
|---|---|
| `discovered` | Dependency records in the configured dev/transitive scope |
| `resolved` | Records with a safe exact package identity and version |
| `checked` | Unique resolved subjects with a usable provider/cache outcome |
| `vulnerable` | Checked subjects with at least one normalized finding |
| `unresolved` | Records whose exact version could not be proven |
| `unsupported` | Records that cannot be mapped safely to the public ecosystem |

Coverage is not inferred from the number of findings. "Zero findings" and "zero
dependencies checked" are different states.

Provider status is:

- `available` when every eligible subject is answered without a provider
  failure;
- `partial` when successful outcomes are mixed with failures, or when
  cancellation/limits intervene; and
- `unavailable` when provider failures leave no fresh-cache or live-provider
  success. An explicitly counted stale fallback may still supply display data,
  but it does not make the provider available.

A view may say "no known vulnerabilities found in audited dependencies" only
for the audited subjects and configured provider. Unresolved, unsupported,
unchecked, truncated, cancelled, or provider-failed work keeps the state partial
or unavailable. The extension never claims complete vulnerability detection or
overall project security.

## UI boundary

Tree, Dashboard, Problems diagnostics, Status Bar, details, and Output Channel
derive from the stored `ScanResult`:

- Tree nodes retain workspace and ecosystem hierarchy before severity/package.
- Dashboard filters are local presentation controls and do not initiate network
  work. Coverage is displayed by canonical ecosystem.
- Diagnostics use parser-provided source offsets or bounded format-aware
  manifest locators. When a source location cannot be established safely, no
  location is invented.
- Details and advisory actions include ecosystem in the selected vulnerability
  identity, preventing an equal package/version in another ecosystem from
  resolving to the wrong record.
- Status cannot display a clean state while dependency or provider coverage is
  incomplete.
- A partial attempt keeps its coverage and counts current while the store holds
  non-reconfirmed findings from the last complete scan in a separate bounded
  finding-only collection. Tree, Dashboard, Details, Status, and Problems label
  that evidence historical; it never contributes provider, dependency,
  coverage, or risk-score arithmetic, and a complete scan clears it.

Remediation is an additional derived layer and never replaces `ScanResult`:

```text
ScanResult -> RemediationAnalyzer -> RemediationAnalysisResult -> UI surfaces
```

Recommendations aggregate findings by an exact dependency occurrence and
origin. They use only normalized provider fixed events, preserve the adapter's
dependency path, and identify a transitive parent only through an unambiguous
direct dependency in the same project/manifest origin. Webviews consume a
structural analysis source injected by extension composition; they do not own
the analyzer or contact a provider. See `docs/remediation.md` for selection and
confidence semantics.

Phase 5B keeps planning and execution separate from analysis:

```text
RemediationRecommendation
  -> RemediationPlanner (read-only, bounded preview)
  -> awaitingApproval -> exact-proposal approval
  -> rebuild and compare plan -> final Apply confirmation
  -> RemediationExecutor (single transaction)
  -> local validation
  -> existing scanner, non-publishing validation result
  -> commit + publish OR exact-byte rollback
```

`RemediationStateMachine` enforces preview, approval, validation, applying,
verification, terminal failure/rollback, stale, unsupported, and manual-review
transitions. `RemediationApprovalRegistry` binds a one-use opaque approval to
the exact proposal and file hashes. A dedicated Remediation webview projects
only bounded state/diff summaries; its row identifiers are resolved back to
current host-owned recommendations before any action.

`RemediationPlanner` classifies each recommendation as `safe`, `preview-only`,
or `unsupported`. A plan owns target paths derived from the stored dependency
origin, current SHA-256 hashes, bounded before/after data, real diffs, warnings,
and validation requirements. A short-lived opaque preview token—not provider
or webview input—selects the internal plan at apply time.

`RemediationExecutor` is the only mutation boundary. It is injected with file,
workspace, recommendation-generation, and scanner-verification interfaces; it
has no process, terminal, task, shell, package-manager, registry, or project-code
execution interface. It rechecks trust, canonical workspace containment,
regular-file identity, reparse state, write access, unsaved editors, hashes,
recommendation evidence, registry provenance, and scan generation immediately
before controlled writes. A process-wide lock permits one transaction.

The current deterministic npm planning subset is deliberately limited to direct
npm dependencies in root non-workspace package-lock v3 projects. It can reuse only
a uniquely proven, already-present target registry artifact with canonical URL
and integrity data, matching placement context, a simple range-preserving
declaration, and a completely valid locally reparsed graph. It never invents or
downloads resolution metadata. The production filesystem adapter cannot prove a
race-safe conditional atomic replacement, so even this plan is exposed as
preview-only in the packaged extension. The transaction engine's `safe` path is
tested through injected atomic adapters; it is not mislabeled as available in a
real workspace. Other cases remain preview-only or unsupported.

Snapshots are bounded exact bytes held only for the transaction. Each atomic
replacement is read back and attributed to the transaction. Rollback restores
only transaction-owned outputs whose identities/hashes still prove ownership,
then verifies the original hashes. This prevents rollback from overwriting a
concurrent external user edit. The controller publishes the validation scan
only after the executor commits; transient failed scan results never become UI
truth. See `docs/remediation-apply.md` for the user-facing safety contract.

All provider strings are treated as untrusted. Webview output is context-escaped
and bounded, uses a restrictive Content Security Policy, and accepts only
validated messages and credential-free HTTPS advisory URLs already present in
the normalized result.

## Resource and execution safety

The scanner, analyzer, and preview planner are read-only static analysis:

- no package-manager, build, restore, test, install, update, download, or script
  command is executed;
- no Python, JavaScript project, Gradle, Maven, Cargo, Go, .NET, or Composer code
  is evaluated;
- manifests and lockfiles are not rewritten by scanning, analysis, startup,
  background work, file saves, workspace changes, or preview; only an explicitly
  approved and finally confirmed `safe` transaction may minimally edit its
  listed targets; the packaged adapter currently offers no such transaction
  capability;
- file discovery, individual reads, parsed collections, graph traversal,
  provider responses, normalized results, cache entries, and elapsed work are
  bounded;
- every multi-root scan shares a 256 MiB aggregate dependency-metadata read
  budget and retains at most 10,000 dependency records across all adapters and
  projects;
- one global scheduler runs no more than four project scans concurrently; and
- cancellation aborts discovery/audit work without atomically replacing the
  last usable result with an incomplete attempt.

The only automatic external dependency-vulnerability traffic is a minimal
`package.ecosystem`, `package.name`, and exact `version` query to the
allowlisted OSV HTTPS endpoint. Source files, manifests, lockfiles, dependency
graphs, environment variables, credentials, and tokens are not uploaded.
Remediation does not add registry or vulnerability-provider traffic. Its
post-write validation reuses the same scanner/provider/cache pipeline.

## Extension points

To add another package manager:

1. implement `PackageManagerAdapter` using bounded static parsing;
2. emit only the shared `Dependency` and project-coverage models;
3. add an explicit canonical mapping only if OSV supports that ecosystem and
   its package identity can be preserved;
4. register the adapter in the workspace scanner; and
5. add deterministic fixtures for resolved, unresolved, unsupported, malformed,
   workspace, graph, limit, and cancellation behavior.

Do not add provider calls to an adapter or manager-specific branches to the UI.
If a package cannot be represented exactly, preserve the gap rather than
guessing.
