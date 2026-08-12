# Dependency Vulnerability Auditor

Dependency Vulnerability Auditor is a defensive VS Code extension that
statically reads dependency metadata, checks eligible exact package versions
against OSV, and presents known dependency vulnerabilities without running
project code or a package manager. It enriches validated CVE identifiers from a
fresh CISA Known Exploited Vulnerabilities catalog, preserves source evidence
and conflicts, derives explainable risk bounds, evaluates a local fail-closed
security policy, and generates CycloneDX JSON 1.6 and SARIF 2.1.0 output.
Eligible npm direct-dependency changes can be previewed as bounded diffs for
manual remediation.

**Dependency Auditor does not automatically modify workspace dependency files in
this release.** Remediation is preview-only/manual for every ecosystem.

Run **Dependency Auditor: Scan Workspace** from the Command Palette, or open the
shield icon in the Activity Bar and use the Dependency Security views. Automatic
startup and change scans are opt-in.

## Project links

- Repository: https://github.com/brahimkedjar/scan_vulnirabilities
- Issues: https://github.com/brahimkedjar/scan_vulnirabilities/issues
- Provider semantics: [docs/providers.md](docs/providers.md)
- Policy and gate: [docs/policy.md](docs/policy.md)
- CycloneDX and SARIF: [docs/sbom.md](docs/sbom.md)
- Privacy and security: [docs/privacy.md](docs/privacy.md) and
  [docs/security.md](docs/security.md)
- Reachability, supply-chain, license, CI, and threat-model boundaries:
  [docs/reachability.md](docs/reachability.md),
  [docs/supply-chain.md](docs/supply-chain.md),
  [docs/license.md](docs/license.md), [docs/ci.md](docs/ci.md), and
  [docs/threat-model.md](docs/threat-model.md)
- RHDA/RHTPA scope comparison:
  [docs/competitive-analysis.md](docs/competitive-analysis.md)

## Supply-chain intelligence in 0.8.0

Version 0.8.0 is the first production Phase 7 slice, not completion of the
broader supply-chain security roadmap. It adds:

- an immutable, provider-neutral evidence model with source observations,
  aliases, freshness, conflicts, confidence reasons, and missing-field state;
- CISA KEV enrichment that matches exact validated CVE aliases locally and
  never treats stale or unavailable evidence as absence;
- per-finding evidence-backed risk lower and upper bounds;
- a bounded security-policy engine that uses the unfiltered findings from the
  latest scan attempt and fails closed on incomplete evidence;
- CycloneDX JSON 1.6 generation with canonical components, safe occurrence
  evidence, proven dependency relationships, vulnerabilities, and completeness
  compositions; and
- SARIF 2.1.0 generation with safe relative locations, deterministic partial
  fingerprints, and coverage notifications.

OSV remains the only live package vulnerability lookup provider. CISA KEV is an
exploitation catalog enrichment, not a package scanner. The provider-neutral
model can represent future sources, but this release does not directly query
NVD or GitHub Advisory Database. CVE and GHSA identifiers in an OSV record
remain OSV-supplied aliases unless another configured source independently
reports them.

## Supported ecosystems and metadata

"Supported" means the adapter safely parses the listed local format. It does not
mean that every language feature can be evaluated statically. Unsupported
syntax, missing resolution metadata, and unsafe package sources are retained as
coverage gaps instead of being guessed.

| Ecosystem / manager | Manifest | Resolution metadata | OSV ecosystem | Status |
|---|---|---|---|---|
| npm | `package.json` | `package-lock.json` or `npm-shrinkwrap.json` v2/v3 | `npm` | Supported |
| Yarn | `package.json` | `yarn.lock` (Classic and supported Berry text formats) | `npm` | Supported |
| pnpm | `package.json` | `pnpm-lock.yaml` v5/v6/v9 | `npm` | Supported |
| Bun | `package.json` | `bun.lock` text format | `npm` | Supported for text locks; `bun.lockb` is detected but unavailable |
| Python requirements | `requirements.txt` and common `requirements-*.txt` variants | Exact `==` pins in the requirements file | `PyPI` | Supported for exact pins |
| Poetry | `pyproject.toml` | `poetry.lock` | `PyPI` | Supported |
| Pipenv | `Pipfile` | `Pipfile.lock` | `PyPI` | Supported |
| Maven | `pom.xml` | Exact direct declarations and local POM properties/dependency management | `Maven` | Supported for statically resolved direct dependencies |
| Gradle | `build.gradle` or `build.gradle.kts` | `gradle.lockfile` where present | `Maven` | Supported for common literal declarations and lock entries |
| Cargo | `Cargo.toml` | `Cargo.lock` v1-v4 | `crates.io` | Supported |
| Go Modules | `go.mod` | Go 1.17+ graph metadata and matching `go.sum` checksum | `Go` | Supported with conservative static resolution |
| NuGet | `*.csproj` or `packages.config` | `packages.lock.json` / `packages.*.lock.json` v1-v3 | `NuGet` | Supported |
| Composer | `composer.json` | `composer.lock` | `Packagist` | Supported |

All seven canonical OSV ecosystems are enabled by default. A canonical setting
may cover several adapters: `npm` enables npm, Yarn, pnpm, and Bun; `PyPI`
enables requirements, Poetry, and Pipenv; `Maven` enables Maven and Gradle.

### Coverage limitations by adapter

- npm lockfile entries are authoritative. Public-registry packages are eligible;
  workspace, local-file, Git, and custom-remote roots are not submitted as npm
  releases. Supported registry children can still be traversed. Registry
  provenance is also checked against bounded workspace-local `.npmrc`,
  `.yarnrc`, `.yarnrc.yml`, and `bunfig.toml` files.
- Yarn supports Classic locks and Berry lock metadata versions 4-8. pnpm
  supports lockfile major versions 5, 6, and 9. Unknown lock formats are reported
  as unsupported. Workspace/local/protocol references are never turned into
  public registry versions.
- Bun `bun.lock` text/JSONC versions 0-2 are parsed. `bun.lockb` is only
  detected; the extension reports "bun.lockb detected but resolved dependency
  extraction is unavailable." It does not execute Bun to convert the file.
- Python requirements preserve extras and environment-marker metadata, normalize
  names using the PyPI/PEP 503 convention, and query only exact `==` pins.
  Ranges, unpinned requirements, direct URLs, editable installs, custom indexes,
  and nested requirements includes are unresolved or unsupported.
- Poetry and Pipenv use their lockfiles as the source of resolved versions and
  distinguish production and development groups where the static formats allow
  it. Explicit custom indexes/sources are never reclassified as PyPI merely
  because a lock entry omits provenance. Manifest constraints without a usable
  lock entry remain unresolved.
- Maven preserves `groupId:artifactId` and resolves safe local properties and
  dependency-management versions. Explicit custom repositories make reached
  coordinates unsupported because Maven Central provenance cannot be proven.
  Applicable workspace POMs, `.mvn/{maven,jvm}.config`, and
  `.mvn/extensions.xml` are inspected; selected settings, alternate POMs,
  local/offline repositories, and build/core extensions fail closed. A POM does
  not contain Maven's resolved transitive graph, profiles are not activated,
  and system-scope or dynamic coordinates are not guessed.
- Gradle recognizes common literal dependency calls such as
  `implementation("group:name:version")` and test/API variants. A lockfile can
  prove exact versions for statically matched direct declarations. Because the
  lock format does not preserve parent edges, unmatched entries remain visible
  as unresolved transitive coverage and are not submitted to OSV. Arbitrary
  Groovy/Kotlin expressions, version catalogs, plugins, and build logic are not
  executed. Without lock state, declarations are requested versions only and
  remain unresolved; exact selected versions are not guessed. Repository
  declarations in applicable workspace build and settings scripts are
  inspected; explicit custom repositories, applied scripts, and nontrivial
  plugins remain unsupported.
- Cargo uses `Cargo.lock` as the resolved graph, preserves renamed dependencies,
  and handles statically representable workspace declarations. Local, Git, and
  custom-registry package roots are not queried as crates.io releases.
- Go uses the canonical module path from `go.mod`. Direct and `// indirect`
  requirements are represented, exact remote replacements are handled
  conservatively, and local replacements are unsupported. A dependency becomes
  queryable only when Go 1.17+ `go.mod` graph semantics and a matching `go.sum`
  entry jointly support the selected version. Older/incomplete graphs remain
  unresolved; parent paths beyond `go.mod` are unavailable.
- NuGet uses lock targets for resolved direct/transitive packages when present.
  `PackageReference` constraints without a lock remain unresolved.
  `packages.config` supplies exact installed versions but is a flat list and
  cannot prove dependency relationships. Applicable workspace `NuGet.Config`,
  project `RestoreSources`, and ancestor `Directory.Build.props` restore-source
  declarations are inspected before a package is treated as a NuGet.org release.
- Composer uses `composer.lock` for resolved package relationships and
  `require`/`require-dev` classification. Manifest constraints without a lock
  remain unresolved. Custom and path repository packages are not mapped to
  Packagist without provable public provenance.

Where a manifest and lockfile can be reconciled statically, a missing,
incompatible, unreachable, or stale/mismatched lock selection is retained as a
coverage gap instead of being submitted as an exact installed version. This is
constraint/graph reconciliation, not a claim that every form of lockfile
staleness can be detected without running the package manager.

Source provenance is necessarily workspace-bounded. User- or machine-level
package-manager configuration, Maven settings outside the workspace, Gradle
init/user configuration, and NuGet configuration outside the workspace are not
observable. When workspace metadata selects an external or otherwise
unresolvable source configuration, affected identities fail closed rather than
being assumed to come from a public registry.

## Multi-root workspaces and monorepos

Every VS Code workspace folder is scanned, and each detected dependency project
retains its workspace folder, project root, manifest, lockfile, package manager,
and ecosystem. Results from unrelated projects are not combined into one
dependency graph.

The npm, Yarn, pnpm, Bun, and Cargo adapters recognize statically representable
workspace metadata. One global scheduler runs at most four project scans at a
time across all adapters and all folders in a multi-root workspace. Provider
work is deduplicated by canonical
`ecosystem + package name + exact version`, so the same OSV subject is queried
once while project-level provenance and coverage remain separate.

## Ecosystem mapping and package identity

Adapters emit one ecosystem-independent `Dependency` model. A single mapping
layer validates and converts that model to an exact OSV package identity:

| Adapter identity | Canonical OSV identity |
|---|---|
| npm, Yarn, pnpm, Bun | `npm` package name, including scope |
| Python requirements, Poetry, Pipenv | `PyPI` normalized project name |
| Maven, Gradle | `Maven` `groupId:artifactId` |
| Cargo | `crates.io` crate name |
| Go Modules | `Go` full module path |
| NuGet | `NuGet` package ID |
| Composer | `Packagist` `vendor/package` |

Canonical identity is never shortened: `org.springframework:spring-core` stays a
Maven coordinate and `github.com/gin-gonic/gin` stays a Go module path. Invalid,
ambiguous, local, dynamic, unresolved, and unsupported identities are not sent
to OSV.

## Coverage and result semantics

Coverage is reported per project and per canonical ecosystem:

- **Discovered**: dependency records in the configured scan scope.
- **Resolved**: records with a safe exact package version.
- **Checked**: resolved dependency records whose canonical subject was answered
  successfully by a fresh cache, OSV, or an explicitly counted stale fallback.
  Provider totals separately report deduplicated query subjects.
- **Vulnerable**: checked dependency records with one or more known findings.
- **Unresolved**: declarations for which an exact version could not be proven.
- **Unsupported**: sources or identities that cannot be represented safely.

The Tree View, Dashboard, Problems panel, Output Channel, and Status Bar all use
the same stored scan result. The Dashboard includes ecosystem filters and a
coverage table. Problems diagnostics include ecosystem context and point to a
safe manifest location when the static parser can identify one.

When a partial refresh follows a complete scan, newly confirmed findings and
current coverage remain authoritative. Findings from the last complete scan
that were not reconfirmed are retained separately, visibly labeled historical,
and capped at 10,000. Historical evidence appears in Tree, Dashboard, Details,
Status, and Problems without increasing current provider, dependency, coverage,
or risk-score totals. A subsequent complete scan clears that retained evidence.

The extension reports **known vulnerabilities detected from the configured
provider**. It never claims that all vulnerabilities were detected or that a
project is secure. "No known vulnerabilities found in audited dependencies" is
only a provider result for checked subjects. If dependencies are unresolved,
unsupported, unchecked, truncated, cancelled, or affected by a provider error,
the UI reports partial or unavailable coverage and does not present a clean
status. The Status Bar includes the unresolved count when applicable.

The stored result also retains an immutable unfiltered normalized finding set.
`minimumSeverity` remains a presentation/diagnostic filter; policy and export
code use the unfiltered set when available. Provider totals are cross-checked so
missing records cannot silently turn a gate or exported report clean.

## Security UI

- **Dependency Security Tree View** groups results by workspace, ecosystem,
  severity, package, and advisory.
- **Dependency Security Dashboard** presents severity totals, coverage by
  ecosystem, provider status, top vulnerable dependencies, filters, and the last
  usable scan.
- **Vulnerability Details** shows the canonical ecosystem/package identity,
  exact version, dependency type/path, CVSS data, affected/fixed versions,
  timestamps, identifiers, and validated advisory references.
- **Problems integration** marks direct declarations and, where a safe
  relationship and source location exist, the direct introducer for transitive
  findings.
- **Status Bar** distinguishes scanning, findings, complete no-known-findings,
  incomplete coverage, and provider-unavailable states.

### Remediation Intelligence

For stored findings, the extension derives a local remediation candidate from
the fixed-version events already returned by the configured provider. Direct
dependencies can receive an exact recommended upgrade. Transitive findings are
traced through the stored dependency path and name a parent remediation point
only when that relationship is unambiguous; no parent version is invented.

Recommendations include confidence and a non-authoritative compatibility-risk
indicator. Multiple advisories on the same dependency occurrence are combined
only when one provider-listed candidate can be established conservatively. A
finding with no provider fix is labeled **No known fixed version**, while an
unresolved, ambiguous, or conflicting case requires manual review. Remediation
coverage means the proportion of displayed findings with a calculated
candidate; it never means that dependencies have been changed or are secure.

Use **Dependency Auditor: Show Remediation** to inspect the latest complete scan
without rescanning or contacting OSV. See `docs/remediation.md` for candidate
selection, confidence, transitive-path, and limitation rules.

### Remediation preview and manual verification

For an eligible recommendation, **Review Fix** creates a read-only preview with
current file hashes and real diffs. Previewing is not approval and does not
modify the workspace. The packaged adapter exposes no automatically applicable
plan in this release; all remediation is manual.

The deterministic npm preview subset is deliberately narrow: a direct npm dependency in
a root, non-workspace package-lock v3 project, using a simple exact/caret/tilde
range, where the exact target registry artifact is already present and the
complete generated graph validates locally. Production automatic remediation remains disabled
because the host file primitive cannot prove a race-safe conditional atomic
replacement. The extension never invents npm
integrity, resolved URL, checksum, graph, or placement data. Other npm cases and
other ecosystems remain `PREVIEW-ONLY` or `UNSUPPORTED`.

The transaction engine is tested with injected atomic filesystem adapters: edits
are minimal, preserve UTF-8 BOM/newline style, validate through the existing
scanner, and trigger exact-byte rollback plus hash verification on failure.
Those tests do not make workspace apply available. See
`docs/remediation-apply.md` for the complete safety model, capability table, and
limitations.

The activity bar also contains a dedicated **Remediation** view. It presents
the exact dependency occurrence, current and proposed versions, vulnerability
IDs, rationale, confidence/risk, bounded real diffs, read-only Git advisory
state, and the proposal's transition history. Its buttons follow the explicit
state machine. In the packaged host every proposal currently terminates as
preview-only/manual review because the required atomic replacement primitive is
unavailable; automatic Apply is therefore not offered.

For preview-only remediation, the view provides **Open Diff**, **Copy Patch**,
and **Open File** actions. These actions use the controller's current preview
token and bounded file index; the webview never supplies paths or file content,
and no workspace file is modified. After applying a change manually, run a
fresh scan to verify whether the targeted finding is fixed, still vulnerable,
incomplete, provider-unavailable, or unknown.

Phase 5C is complete as a verified manual remediation workflow. Public Node/VS
Code APIs expose path-based replacement without an operation that atomically
checks both the expected file identity and exact expected bytes, so production
Apply is unavailable in this release. See
`docs/phase5c-safety-assessment.md` and `docs/remediation-production.md` for
the proof boundary, capability matrix, refusal conditions, manual workflow, and
post-scan verification model.

Dashboard and details content treats every provider field as untrusted. HTML is
context-escaped and bounded. Webviews use a strict Content Security Policy and
have no `eval`, dynamic code generation, or inline event handlers. Advisory
actions accept only credential-free HTTPS URLs present in the selected
normalized provider result.

### Risk indicators

The Dashboard's aggregate Dependency Risk Score remains a deterministic
finding-density indicator, not a statement about overall application security.
Finding weights are Critical=20, High=10, Medium=4, Low=1, Unknown=0:

```text
min(100, round(weighted finding points / (20 * dependencies scanned) * 100))
```

Provider and dependency coverage are displayed separately. Filtering findings
by severity cannot turn hidden findings or incomplete coverage into a clean
result.

Phase 7 also adds an explainable per-finding risk model. Its 100 possible
points are normalized severity (40), CVSS (30), fresh CISA KEV evidence (20),
and reachability (10). The result contains the evidence-supported lower score,
an upper bound that exposes missing evidence, factor-by-factor reasons, and an
evidence-completeness state. Missing evidence adds zero asserted points; it is
never silently converted to low risk. This release has no source/call-graph
reachability engine, so reachability is explicitly `UNKNOWN` and its 10 points
remain uncertainty.

### Policy and standard output

After a scan, use these Command Palette actions:

- **Dependency Auditor: Evaluate Security Gate** evaluates
  `dependencyAuditor.securityPolicy` against the latest attempt. When
  `dependencyAuditor.enableCisaKevEnrichment` is enabled, this explicit action
  also downloads or reuses the public KEV catalog and prints bounded risk-factor
  and gate-reason evidence in the Output Channel.
- **Dependency Auditor: Export CycloneDX JSON 1.6** opens VS Code's native Save
  dialog and exports the latest attempt.
- **Dependency Auditor: Export SARIF 2.1.0** opens the same trusted save boundary
  for SARIF.

No export path or file content is accepted from command arguments. Cancelling
the Save dialog performs no write.

The local security-policy engine supports bounded severity/CVSS counts and
thresholds, required absence from fresh CISA KEV evidence, exact canonical
ecosystem/package allow and block rules, and expiring advisory ignores. It
evaluates unfiltered findings from the latest attempt. Invalid policy,
incomplete coverage, provider records hidden from evaluation, cancellation, or
required unknown evidence cannot pass. See [docs/policy.md](docs/policy.md).

CycloneDX JSON 1.6 and SARIF 2.1.0 builders produce deterministic, bounded
output from stored scan results. They retain unfiltered known findings, use safe
workspace-relative locations only, and label incomplete source coverage.
Relationships are emitted only when a static parser proved them. This release
does not implement CycloneDX XML, SPDX, SBOM import/diff, signing, attestation,
or a headless scan CLI. See [docs/sbom.md](docs/sbom.md).

## Static analysis and safety

Scanning, analysis, and preview only read bounded dependency metadata. The
extension does not run Python or project code, package lifecycle scripts, or
any of:

- `npm`, `yarn`, `pnpm`, or `bun` install/update commands;
- `mvn` or Gradle/`gradlew` tasks;
- `cargo` commands;
- `go mod` commands;
- `dotnet restore`; or
- Composer commands or scripts.

The transaction engine accepts writes only through an injected primitive that
proves race-safe atomic replacement; the packaged production adapter does not
claim that guarantee, so all current workspace remediation is preview-only.
Startup, background scans, file saves,
workspace changes, detection, details, tree/dashboard actions, and preview do
not write project files. Detection and parsing have bounded file counts, graph depth/edge limits, and cancellation. Across the complete
multi-root scan, dependency metadata reads share a 256 MiB aggregate budget, at
most 10,000 dependency records are retained, and at most four project scans run
concurrently. A reached limit becomes a coverage gap rather than a clean result.

## Privacy, network, and cache behavior

For each eligible exact dependency, the extension sends only a request shaped
like this to `https://api.osv.dev/v1/query`:

```json
{
  "package": {
    "ecosystem": "PyPI",
    "name": "requests"
  },
  "version": "2.31.0"
}
```

It does not upload source files, manifests, lockfiles, dependency graphs,
environment variables, `.env` files, credentials, or tokens. OSV transport
requires HTTPS, uses an exact host allowlist, rejects redirects, and enforces
request/response limits and timeouts. At most five vulnerability requests run
at once.

CISA KEV enrichment downloads the public catalog with an HTTPS `GET` from its
fixed `www.cisa.gov` feed URL. That request contains no workspace path, package
identity, dependency data, source content, or credentials. CVE matching happens
locally. Only a fresh complete catalog can support `NOT_LISTED`; no CVE alias,
stale catalog, cancellation, validation failure, or unavailable catalog yields
`UNKNOWN` instead. See [docs/providers.md](docs/providers.md) and
[docs/privacy.md](docs/privacy.md).

Successful OSV responses, including successful empty responses, are cached in
VS Code `globalState`. Cache keys include
`provider + ecosystem + canonical package name + version`, preventing results
from one ecosystem or version from satisfying another. Provider and network
errors are never cached as safe. If a refresh fails, an expired successful value
may be shown only as an explicitly counted stale fallback; coverage remains
partial or unavailable. **Refresh Vulnerability Database** clears the vulnerability cache
before using the normal scan pipeline.

Cancellation stops new work and aborts active requests. A cancelled attempt does
not replace the displayed usable diagnostics or partially commit newly fetched
cache entries.

## Settings

- `dependencyAuditor.enabled`: enable scanning and related UI (default `true`).
- `dependencyAuditor.scanOnStartup`: opt in to scanning after activation
  (default `false`).
- `dependencyAuditor.scanOnChange`: opt in to debounced rescans after supported
  metadata changes (default `false`).
- `dependencyAuditor.enabledEcosystems`: canonical OSV ecosystem values enabled
  for detection and queries. Defaults to
  `["npm", "PyPI", "Maven", "crates.io", "Go", "NuGet", "Packagist"]`.
  Values are case-sensitive; an empty array disables all adapters.
- `dependencyAuditor.minimumSeverity`: lowest normalized severity displayed.
  `UNKNOWN` includes all findings and unknown severity is never silently hidden.
- `dependencyAuditor.includeDevDependencies`: include dependencies exclusively
  classified as development dependencies (default `true`).
- `dependencyAuditor.includeTransitiveDependencies`: include resolved
  transitive dependencies (default `true`).
- `dependencyAuditor.cacheDuration`: successful-response lifetime in hours
  (default 24).
- `dependencyAuditor.networkTimeout`: timeout for each OSV attempt in
  milliseconds (default 10000).

Changes to `cacheDuration` and `networkTimeout` take effect when the extension
host next activates. Scan triggers, ecosystem selection, dependency scope, and
severity filters are read for each scan.

## Severity and version handling

OSV records are validated and normalized before UI code uses them. Authoritative
non-Git fixed-version events are retained in a bounded normalized collection for
local remediation analysis. npm uses
strict semantic-version handling for exact versions and supported OSV range
events. Other ecosystems are queried with their canonical exact version, and
ecosystem-specific ordering is not guessed locally.

Severity resolution prefers a valid CVSS score/vector, then a recognized
qualitative provider rating, and otherwise uses `UNKNOWN`. A remediation target
is selected only from provider-supplied fixed events; inconsistent or
incomparable evidence becomes manual review rather than a guessed version.

## Development and verification

Requirements:

- Node.js 20.17 or newer
- npm 11 or newer
- VS Code 1.125 or newer

```sh
npm install
npm test
npm audit
npm run package:check
npm run package:vsix
```

Unit tests use deterministic local parser fixtures and mocked OSV responses; they
do not require the live OSV service. Open this directory in VS Code and press
`F5` for an Extension Development Host when performing an interactive smoke
test.

See [docs/architecture.md](docs/architecture.md) for the adapter contract,
unified models, provider and enrichment boundaries, cache keys, intelligence,
policy, export, and coverage flows.

## Phase boundary

Version 0.8.0 delivers the first bounded Phase 7 slice; it is not the entire
supply-chain platform roadmap. It intentionally does not include unattended or
scheduled fixes, package-manager execution, dependency update commands, a
headless scanner CLI, CI job/PR integration, live NVD/GHSA providers, source or
call-graph reachability, container analysis, license analysis, package-health
or typosquatting/provenance detection, CycloneDX XML, SPDX, SBOM import/diff,
signing/attestation, centralized reporting, or arbitrary build-tool evaluation.
SARIF and CycloneDX support currently means bounded report generation over a
completed extension scan, not a standalone CI scanner.

Marketplace publication uses the public repository and issue tracker linked
above.
