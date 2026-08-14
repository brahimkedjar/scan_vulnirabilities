# Dependency Vulnerability Auditor

Dependency Vulnerability Auditor is a local-first VS Code extension and
headless scanner for statically discovered dependency metadata. It maps exact,
proven package coordinates to OSV, preserves incomplete coverage as an explicit
security state, and can enforce a bounded CI security gate.

The scanner does not execute package managers, build tools, project code,
lifecycle scripts, containers, terminals, or Git commands. It does not claim
that a project is secure merely because a configured provider returned no
findings.

Repository: <https://github.com/brahimkedjar/scan_vulnirabilities>

## Phase 8 capability boundary

Phase 8 introduces a host-neutral core and a real `dependency-auditor` CLI, but
not every tested core engine is connected to every host yet. The distinction
below is intentional.

| Capability | VS Code host | CLI | Host-neutral core | Current limitation |
| --- | --- | --- | --- | --- |
| Static dependency discovery | Connected | Connected | Connected | Only supported, statically provable formats and exact versions are checked |
| OSV vulnerability lookup | Connected | Connected | Injected provider boundary | Online queries send the minimal package coordinate to OSV |
| CISA KEV enrichment | Explicit Security Gate action | Connected via `gate` | Existing enrichment service | KEV absence is only absence from the consulted CISA catalog |
| Basic security gate | Connected | Connected | Connected | CLI policy uses the bounded version 1 vulnerability policy |
| Advanced evidence policy | Not connected | Connected via `--policy` | Connected | CLI supplies generated license, provenance, and reachability evidence during evaluation |
| JSON, SARIF, CycloneDX, HTML, Markdown, CSV | JSON exports through supported commands | Connected to `scan` and `gate` | Tested builders | `gate` renders KEV evidence; advanced-policy gates also render license, provenance, reachability, and diff evidence |
| License intelligence | Evidence card only | Connected command | Connected | Explicit caller metadata only; not authoritative legal analysis |
| Provenance and anomaly intelligence | Source-eligibility evidence only | Connected command | Connected | No registry/repository metadata is fetched by the analyzer |
| JS/TS/Python static reachability | Not run automatically | Connected command | Connected | `NOT_OBSERVED` never means unreachable or non-exploitable |
| CycloneDX JSON import/diff/merge | Not connected | Connected subcommands | Connected | JSON 1.4-1.6 only; no XML or SPDX |
| Security snapshots, history, baselines | Not persisted | Connected commands | Connected | `snapshot`, `diff`, and `baseline` are CLI lifecycle operations; no VS Code timeline yet |
| Local container archive analysis | Not run automatically | Connected command | Connected | Uncompressed Docker/OCI tar only; dpkg/APK inventory; no OS vulnerability provider |
| Remediation | Preview/manual workflow | Not available | Transaction model tested with injected adapters | Production Apply is disabled for every ecosystem |

An unavailable or not-connected capability is reported as `UNKNOWN`,
`NOT_CONFIGURED`, unsupported, or exit code 2. It is never silently treated as
clean.

## Supported dependency inputs

Thirteen static package-manager adapters map to seven canonical OSV ecosystems:

| Ecosystem | Static adapters and inputs |
| --- | --- |
| `npm` | npm `package-lock.json`/shrinkwrap v2-v3, Yarn Classic/Berry locks, pnpm v5/v6/v9 locks, Bun text locks |
| `PyPI` | requirements files, Poetry, Pipenv |
| `Maven` | Maven POM and Gradle declarations/lock metadata |
| `crates.io` | Cargo manifest and lock metadata |
| `Go` | Go module and checksum metadata |
| `NuGet` | project/package and NuGet lock metadata |
| `Packagist` | Composer manifest and lock metadata |

Dynamic declarations, custom or ambiguous sources, unsupported format
versions, missing locks, unresolved ranges, and graph limits remain coverage
gaps. Binary `bun.lockb` is detected but not parsed.

## VS Code workflow

1. Open a workspace.
2. Run **Dependency Auditor: Scan Workspace**.
3. Review the Dependency Security tree, dashboard, Problems diagnostics, and
   coverage rows.
4. Optionally run **Evaluate Security Gate**, **Export CycloneDX JSON 1.6**, or
   **Export SARIF 2.1.0**.
5. Review remediation proposals in the Remediation view. All production
   remediation remains preview-only and manual.

Opening a dashboard does not trigger a scan. Startup and change scanning are
opt-in settings. CISA KEV is contacted only by an explicit Security Gate action
when enrichment is enabled.

## Headless CLI

The built CLI artifact is `dist/cli/main.js`. A distribution that installs the
package `bin` exposes it as `dependency-auditor`. From a source checkout after
the normal project build, the equivalent command is:

```sh
node dist/cli/main.js scan .
```

Supported production commands are:

```sh
dependency-auditor scan --format text .
dependency-auditor scan --format json --output audit.json .
dependency-auditor scan --sarif --output audit.sarif .
dependency-auditor scan --sbom --output bom.cdx.json .
dependency-auditor gate --fail-on HIGH --format json .
dependency-auditor gate --policy dependency-auditor-policy.json --format json .
```

`--output` exclusively creates a new file and refuses to overwrite an existing
path. The output parent must already be a regular, directly resolved directory;
symlink/junction parents are rejected.

The CLI accepts bounded workspace, environment, severity, timeout, dependency,
file, and byte options. See [docs/cli.md](docs/cli.md) for exact options and
command wiring.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Complete scan and no configured policy violation |
| `1` | Policy violation |
| `2` | Incomplete, cancelled, unknown, offline-without-evidence, or unsupported capability |
| `3` | Invalid arguments, policy, or output configuration |
| `4` | Internal scanner or output failure |

CI must treat every nonzero code as a failed job. The templates in
[docs/ci.md](docs/ci.md) and `.github/workflows/phase8-validation.yml` assume a
trusted, version-pinned CLI is already provisioned on the runner; they never
install or invoke a package manager.

## Security gate

The connected version 1 gate supports severity/CVSS thresholds, critical/high
counts, exact ecosystem/package allow and deny selectors, expiring advisory
exceptions, and optional fresh CISA KEV absence in the VS Code host and the
CLI gate. It uses unfiltered findings and fails closed for malformed policy,
hidden provider records, incomplete coverage, cancellation, or required
unknown evidence.

A minimal CI policy is:

```json
{
  "schemaVersion": 1,
  "minimumSeverity": "HIGH"
}
```

The host-neutral advanced policy API can additionally evaluate explicit
license, provenance, anomaly, static reachability, dependency-scope, coverage,
and provider-confidence evidence. The CLI `gate --policy` accepts this schema
and supplies generated license, provenance, and reachability evidence during
evaluation. EPSS has no configured provider and therefore fails closed when
required.

See [docs/policy.md](docs/policy.md) and [docs/ci.md](docs/ci.md).

## Reporting and evidence engines

- CycloneDX JSON 1.6 and SARIF 2.1.0 exports are connected to completed scans.
- CLI scans also render bounded JSON, self-contained script-free HTML,
  Markdown, and formula-neutralized CSV.
- CycloneDX JSON 1.4-1.6 import, deterministic diff, and merge exist as
  host-neutral APIs. Imported paths, prose, URLs, and secrets are not retained.
- Immutable security snapshots, integrity-protected baselines, and historical
  diffs exist as host-neutral APIs. Absence from incomplete evidence remains
  unknown rather than resolved.
- License, provenance, supply-chain anomaly, reachability, monorepo version
  drift, and local container archive engines are bounded and deterministic.
  The CLI runs license, provenance, reachability, snapshot, baseline, SBOM,
  diff, and container commands; the VS Code extension does not run them
  automatically.

Subsystem details and limitations are linked under [Documentation](#documentation).

## Offline and cache behavior

The VS Code extension has a bounded `globalState` cache for successful OSV
responses and a separate bounded CISA catalog cache. Provider errors are never
cached as a clean result; stale data can be shown only as stale fallback with
incomplete coverage.

The CLI intentionally has no persistent cache. `--no-cache` and `--refresh`
are compatibility options, not evidence of persisted CLI state. `--offline`
makes no network request and returns incomplete when queryable dependencies
need vulnerability evidence. `--offline-db FILE` loads a validated bounded
local advisory database and keeps the run offline; without one the result
stays incomplete rather than clean. See [docs/offline.md](docs/offline.md).

## Security and privacy

Static analysis never invokes:

- npm, Yarn, pnpm, Bun, pip, Poetry, Pipenv, Maven, Gradle, Cargo, Go,
  dotnet/NuGet, or Composer commands;
- project code, build scripts, lifecycle hooks, a shell, a VS Code task, or a
  terminal;
- Docker, Podman, a container daemon, or a container image;
- Git commands, hooks, commits, stashes, resets, or checkouts.

Only canonical ecosystem, package name, and exact version are sent to OSV.
Source, manifests, lockfiles, dependency graphs, environment variables,
credentials, and tokens are not uploaded. The provenance analyzer parses only
caller-supplied metadata and never contacts its URLs. Container analysis accepts
only caller-supplied local archive bytes and never pulls an image.

Filesystem traversal is bounded and no-follow. Network clients require exact
HTTPS host allowlists, reject redirects, and enforce time, response-size,
concurrency, validation, and cancellation limits. Reports escape untrusted
content; HTML uses a restrictive CSP and no executable JavaScript.

See [docs/security.md](docs/security.md), [docs/privacy.md](docs/privacy.md),
and [docs/threat-model.md](docs/threat-model.md).

## Explicit non-capabilities

This release does not implement:

- CycloneDX XML import/export or any SPDX format;
- direct registry/container image pulling or registry authentication;
- Docker/Podman/container execution;
- a persistent CLI cache or an automatically downloaded vulnerability database
  snapshot (a local `--offline-db` file must be supplied by the user);
- VS Code wiring for license, provenance, reachability, snapshot, baseline,
  SBOM, or container commands;
- live NVD, GHSA, EPSS, Snyk, or vendor-advisory providers;
- authoritative legal conclusions, malware verdicts, signature trust, runtime
  reachability, or exploitability proof;
- production dependency Apply, package-manager remediation, automated pull
  requests, or unattended changes.

## Settings

The extension contributes settings for enablement, opt-in startup/change scans,
minimum displayed severity, development/transitive scope, enabled ecosystems,
OSV cache lifetime, network timeout, explicit KEV enrichment, and the version 1
security policy. Settings affect the VS Code host; CLI options are independent.

## Documentation

- [Architecture](docs/architecture.md)
- [CLI](docs/cli.md)
- [CI/CD](docs/ci.md)
- [Security model](docs/security.md)
- [Providers and coverage](docs/providers.md)
- [Policy](docs/policy.md)
- [License intelligence](docs/license-intelligence.md)
- [Provenance and anomalies](docs/provenance.md)
- [Static reachability](docs/reachability.md)
- [SBOM and reports](docs/sbom.md)
- [Container archive security](docs/container-security.md)
- [Offline behavior](docs/offline.md)
- [Snapshots, baselines, and history](docs/security-history.md)
- [Remediation](docs/remediation.md)
- [Competitive analysis](docs/competitive-analysis.md)

## Development and verification

Requirements are Node.js 20.17 or newer, npm 11 or newer, and VS Code 1.125 or
newer.

```sh
npm install
npm test
npm audit --omit=dev
npm run package:check
npm run package:vsix
```

Tests use local fixtures and injected providers unless a separately named live
smoke is run. Development and packaging commands are not part of scanner
runtime behavior.

Phase 9 has not been started. The extension is not published automatically and
does not request Marketplace or repository credentials.
