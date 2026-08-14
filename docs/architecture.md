# Architecture

Dependency Vulnerability Auditor now has two hosts over shared static-analysis
code:

```text
VS Code host                         Headless CLI host
workspace.fs, UI, globalState        Node filesystem, stdout/stderr, exit code
             \                       /
              \                     /
               host-neutral Phase 8 core
          discovery / parsing / evidence / reports
                          |
               validated provider boundary
                          |
                         OSV
```

The Phase 8 core does not import `vscode`, create webviews, or own a shell. Its
ports cover filesystem access, clock, cancellation, and logging. Networking is
injected into scanning; pure evidence engines receive already collected data.

## Connected scan path

Both hosts reuse the same thirteen parser families. The headless path is:

```text
requested roots
  -> no-follow NodeFileSystem roots
  -> bounded static discovery
  -> StaticParserBridge
  -> unified Dependency records
  -> canonical OSV identity mapping
  -> injected VulnerabilityProvider
  -> normalized ScanResult and coverage
  -> gate/report output
```

The extension uses its existing VS Code workspace adapters, shared dependency
and vulnerability models, scan-result store, diagnostics, tree, dashboard,
policy, export, and remediation-analysis layers.

Neither path executes a package manager to resolve missing state. A requested
range is not promoted to an installed version. A missing, ambiguous, custom,
or unsupported source becomes a structured coverage gap.

## Host contracts

`src/core/host/HostContracts.ts` defines the core filesystem, clock, logger,
and cancellation surface. `NodeFileSystem` is the CLI implementation. It:

- resolves one regular root without following a link/reparse component;
- keeps reads within the opened root;
- rejects traversal, special files, and identity changes;
- bounds directory enumeration and UTF-8 file reads; and
- exposes no write or process-execution method.

This filesystem is for static analysis. It is separate from remediation's much
stronger conditional atomic replacement contract. The packaged remediation
adapter cannot satisfy that write contract and remains preview-only.

## Host-neutral Phase 8 engines

| Area | Main module | What it establishes |
| --- | --- | --- |
| Discovery | `core/discovery/StaticDependencyDiscovery` | Bounded project/file inventory for thirteen package-manager families |
| Headless scan | `core/scanner/HeadlessScanner` | Static parse, OSV audit, coverage, cancellation, and timeout orchestration |
| License | `core/license/LicenseIntelligence` | Policy over explicit supported license metadata; never a legal conclusion |
| Provenance | `core/provenance/ProvenanceIntelligence` | Local classification of caller-supplied registry/integrity/history evidence |
| Reachability | `core/reachability/*` | Bounded JS/TS/Python import/reference observations from supplied entrypoints |
| Monorepo | `core/monorepo/MonorepoVersionIntelligence` | Cross-project drift and same-project multi-version evidence |
| Policy | `core/policy/AdvancedPolicyEngine` | Optional multi-dimensional evaluation over explicit evidence inputs |
| SBOM | `core/sbom/*` | CycloneDX JSON import, validation, deterministic diff, and merge |
| Snapshot | `core/snapshot/*` | Canonical snapshots, SHA-256 baselines, and evidence-aware historical diff |
| Container | `core/container/ContainerArchiveAnalyzer` | Local uncompressed Docker/OCI tar and dpkg/APK inventory analysis |
| Reporting | `core/reporting/SecurityReport` | Bounded JSON/HTML/Markdown/CSV model and safe rendering |
| Security | `core/security/BoundedJson` | Duplicate/prototype-key rejection, canonical JSON, hashing, and limits |

These modules are tested APIs. The CLI wires scan/gate, scan reporting, and
the license, provenance, reachability, snapshot, diff, baseline, SBOM, and
container commands. Commands return exit code 2 instead of success when the
required evidence remains unknown or unsupported. The VS Code dashboard shows
their evidence state but does not run them automatically.

## Package-manager adapters

| Family | Static subset | OSV ecosystem |
| --- | --- | --- |
| npm | `package.json`, package-lock/shrinkwrap v2-v3 | `npm` |
| Yarn | Classic/Berry locks and workspace manifests | `npm` |
| pnpm | v5/v6/v9 lock data and importers | `npm` |
| Bun | text locks; binary locks are an explicit gap | `npm` |
| requirements | Exact supported requirement pins | `PyPI` |
| Poetry | `pyproject.toml` and Poetry lock | `PyPI` |
| Pipenv | Pipfile and Pipfile lock | `PyPI` |
| Maven | Safe statically declared coordinates | `Maven` |
| Gradle | Literal declarations and lock selections | `Maven` |
| Cargo | manifest and lock graph | `crates.io` |
| Go Modules | module/checksum evidence | `Go` |
| NuGet | project/packages and lock metadata | `NuGet` |
| Composer | manifest and lock graph | `Packagist` |

Manager-specific parsers never contact OSV. The single mapper validates
canonical ecosystem, package name, and exact version before the provider sees a
subject.

## Provider and evidence separation

Three concepts remain separate:

1. OSV is the connected live package vulnerability provider.
2. Provider-neutral intelligence retains normalized observations, source,
   freshness, conflicts, and missing evidence within one exact coordinate.
3. CISA KEV is optional exploitation enrichment matched locally to validated
   CVE aliases; it is not a package vulnerability provider.

The exact coordinate is:

```text
ecosystem + canonical package name + exact installed version
```

Aliases never merge different coordinates. Conflicts remain visible rather
than being collapsed into an invented consensus.

## Coverage and fail-closed state

Coverage tracks discovered, resolved, checked, vulnerable, unresolved, and
unsupported records by project and ecosystem. Provider status is available,
partial, or unavailable. A stale fallback can provide historical display data
but cannot restore complete coverage.

The CLI reduces this evidence to `complete`, `incomplete`, or `cancelled` and
uses exit code 2 for the latter two. Security decisions consume unfiltered
findings and cross-check provider-reported totals, so a UI severity filter
cannot authorize a pass.

## Reporting architecture

SARIF and CycloneDX export are bounded projections of immutable scan results.
The generic report model can additionally accept explicit license, provenance,
reachability, anomaly, KEV, remediation, policy, and diff evidence, but the CLI
populates license, provenance, reachability, KEV, policy, and diff collections
for gate reports when the corresponding engines run.

HTML is self-contained, has no script, and declares a CSP of `default-src
'none'`. Markdown escapes structural text. CSV prefixes formula-like fields.
Absolute workspace locations are reduced to safe relative evidence or omitted.

## Snapshot and baseline architecture

Snapshot builders canonicalize and hash validated JSON. Baselines contain an
independent digest. Diffs separate proven additions/removals from unknown
absence when either side has incomplete evidence. Nothing is persisted
automatically. The CLI `snapshot`, `diff`, `baseline create`, and
`baseline compare` commands are connected; the VS Code extension does not
persist snapshots automatically.

## Resource model

Defaults are deliberately below hard ceilings. The CLI defaults to 100,000
visited entries, 10,000 dependency records, 256 MiB of candidate dependency
metadata, and a 120-second overall timeout. Engines add their own file, byte,
node, edge, path-depth, record, and output limits. Reaching a limit changes
coverage; it never truncates silently into a clean result.

See [security.md](security.md), [providers.md](providers.md), and
[cli.md](cli.md) for the operational boundaries.
