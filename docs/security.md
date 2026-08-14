# Security model

Dependency Vulnerability Auditor is a defensive static analyzer. Its primary
runtime guarantee is that dependency discovery, vulnerability lookup, policy,
reporting, and evidence analysis do not execute workspace code or package
manager commands.

## Trust boundaries

```text
untrusted paths and dependency metadata
  -> no-follow bounded filesystem and parsers
  -> exact Dependency or explicit gap
  -> canonical public-package mapper
  -> exact-host HTTPS provider
  -> bounded validation and normalized findings
  -> coverage-aware gate and escaped reports
```

Separate optional inputs - CISA KEV, imported CycloneDX JSON, local container
archive bytes, source text, policy files, and caller-supplied evidence - are
validated and bounded before entering a domain model.

## Prohibited execution

Scanner runtime does not invoke:

- npm, Yarn, pnpm, Bun, pip, Poetry, Pipenv, Maven, Gradle, Cargo, Go,
  dotnet/NuGet, or Composer;
- package lifecycle scripts, project modules, build files, shell commands,
  terminals, or VS Code tasks;
- Git commands or hooks;
- Docker, Podman, container daemons, image pulls, or container processes; or
- arbitrary executables supplied by workspace metadata.

Parsers read build/dependency declarations as untrusted text. Unsupported
dynamic expressions are not evaluated.

## Filesystem controls

The headless `NodeFileSystem` resolves regular local roots and rejects traversal,
symlink/reparse components, special files, identity changes, excess directory
entries, oversized reads, invalid UTF-8, and cancellation. Discovery skips
common generated/vendor/VCS directories and does not follow directory links.

CLI reports are written only by explicit `--output`. The implementation uses
exclusive create, refuses existing targets, requires a directly resolved
regular parent directory, writes with restrictive mode where supported, syncs,
and verifies the resulting size. It never overwrites a report.

Production remediation has a separate identity-plus-exact-hash atomic CAS
contract. Public Node filesystem APIs cannot prove it across supported hosts,
so production Apply is disabled before staging or writing.

## Network controls

- OSV requests use HTTPS and exact `api.osv.dev` allowlisting.
- The extension's optional KEV request uses the fixed official CISA HTTPS feed.
- Redirects are rejected.
- Timeouts, retries, response bytes, pagination, concurrency, validation, and
  cancellation are bounded.
- Only supported canonical package identity and exact version are sent to OSV.
- Provenance URL fields are parsed locally and never contacted.
- Container images are never pulled; only caller-supplied archive bytes can be
  analyzed through the core API.

There is no direct NVD, GHSA, EPSS, registry, repository, or arbitrary URL
provider in this release.

## Fail-closed rules

- An unresolved, ambiguous, custom-source, malformed, or truncated dependency
  is not reclassified as a public registry package.
- Provider failure, stale fallback, offline-without-evidence, cancellation,
  limits, and hidden provider records cannot produce complete coverage.
- Unknown severity/CVSS/KEV evidence fails when a configured rule requires it.
- Advanced evidence rules fail or warn according to explicit unknown-evidence
  policy. EPSS always fails when required because no provider is configured.
- `NOT_OBSERVED` reachability does not mean unreachable or non-exploitable.
- Provenance anomaly signals are investigation evidence, never malware or
  vulnerability verdicts.
- Unknown license metadata is never inferred from package identity.
- Container inventory without an OS-package advisory provider cannot claim a
  clean image.
- A snapshot/SBOM diff does not report a resolved item when incomplete evidence
  makes absence ambiguous.

## Untrusted parser controls

Bounded JSON rejects duplicate keys and prototype-pollution keys before
canonicalization. SBOM import retains only normalized identity, relationship,
rating, hash, and coverage evidence; it omits untrusted paths, arbitrary prose,
URLs, and secrets. Tar parsing checks headers, checksums, entry type/path,
duplicates, links, declared sizes, aggregate size, digest, layer count, and
package database bounds. Compressed container layers are explicit unsupported
coverage, not silently skipped clean.

## Output controls

Terminal strings have controls, ANSI-sensitive characters, and bidirectional
controls neutralized and are bounded. Webviews use strict CSP and escaped
host-owned data. HTML reports contain no executable JavaScript and use
`default-src 'none'`. Markdown and CSV have context-specific escaping; CSV
neutralizes spreadsheet formulas.

Command/webview callers cannot provide remediation bytes, arbitrary export
paths, or advisory URLs. The extension resolves opaque selections against
current host-owned state.

## Cache and offline controls

The extension caches validated successful OSV responses in bounded VS Code
`globalState`; CISA KEV uses a distinct cache. Errors are not stored as empty
successes. A stale cache entry remains stale evidence.

The CLI has no persistent cache. `--offline` makes zero network calls and
returns incomplete when vulnerability evidence is needed unless a local
database is supplied. `--offline-db FILE` loads a validated bounded local
advisory database; the offline run then queries only that local provider and
reports its age, validity window, and payload digest.

## Security regression areas

Tests cover traversal, symlink/junction/reparse behavior, TOCTOU identity
changes, read/output bounds, cancellation, malformed providers, SSRF controls,
duplicate/prototype JSON keys, unsafe SBOM references, tar traversal/links/
checksums/digests, XSS, Markdown/CSV injection, log controls, stale evidence,
policy unknowns, and no-write remediation refusal.

## Reporting security issues

Use the repository's private security-reporting facility when available. If it
is unavailable, open a minimal issue without exploit details or secrets and ask
for a private contact channel:

<https://github.com/brahimkedjar/scan_vulnirabilities/issues>
