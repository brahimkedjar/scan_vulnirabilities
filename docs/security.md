# Security model

Dependency Vulnerability Auditor is a defensive static analyzer. Its core
security property is that discovering dependencies and producing vulnerability,
intelligence, policy, risk, SBOM, and SARIF results does not execute workspace
code or package-manager commands.

## Trust boundaries

```text
Untrusted workspace metadata
        -> bounded static parsers
        -> resolved Dependency records or explicit coverage gaps
        -> canonical public-package identity validation
        -> allowlisted OSV request
        -> bounded provider validation and normalization
        -> immutable scan result

Untrusted public KEV catalog
        -> bounded catalog validation
        -> exact local CVE matching
        -> freshness-aware exploitation assessment

Immutable scan result
        -> intelligence/risk/policy/export modules
        -> escaped UI or explicit local export
```

Package-manager adapters cannot contact vulnerability providers. Provider code
cannot parse the workspace. Policy, risk, aggregation, CycloneDX, and SARIF
modules are pure or injected-boundary modules and do not own a shell, terminal,
task, package-manager, registry-download, or project-code execution interface.

## Execution boundary

The extension does not invoke npm, Yarn, pnpm, Bun, Python, Poetry, Pipenv,
Maven, Gradle, Cargo, Go, dotnet/NuGet, Composer, a shell, a terminal, or a VS
Code task to discover, resolve, scan, repair, or export dependencies. Dynamic
build expressions and missing graph data become unresolved or unsupported
coverage instead of being evaluated or guessed.

Production remediation remains preview-only/manual. The tested transaction
engine requires a race-safe conditional atomic replacement primitive, and the
packaged adapter does not claim that the available host primitive supplies that
guarantee.

## Fail-closed semantics

- An unresolved or custom-source dependency is not reclassified as a public
  package.
- Provider failure, stale fallback, cancellation, parser truncation, and
  unchecked dependencies cannot produce a clean scan state.
- A stale or unavailable KEV catalog produces `UNKNOWN`, never a synthetic
  not-exploited result.
- Missing CVSS, severity, exploitation, or reachability evidence contributes no
  invented risk points and remains visible as uncertainty.
- The security gate cannot pass invalid policy, malformed input, hidden
  provider findings, incomplete latest-attempt coverage, cancellation, or a
  required evidence field that is unknown.
- SBOM and SARIF exporters label incomplete coverage and omit unsafe locations;
  they do not invent dependency edges or workspace-relative paths.

## Untrusted output handling

Provider and workspace strings are treated as untrusted throughout rendering.
Webview values are context-escaped and bounded. Webviews use a restrictive
Content Security Policy with no `eval`, dynamic code generation, or inline
event handlers. Host actions resolve opaque, host-owned selections rather than
accepting arbitrary paths or URLs from webview messages.

Exports validate tokens, timestamps, URLs, collection sizes, graph sizes,
locations, result counts, and output byte size. Stable hashes are used for
component references and SARIF fingerprints; they are identifiers, not digital
signatures.

## Current non-capabilities

The current slice does not provide:

- a source-code or call-graph reachability engine;
- container image, Dockerfile build, or base-image analysis;
- package license, maintainer-health, provenance/signature, typosquatting, or
  dependency-confusion analysis;
- live NVD or GitHub Advisory Database queries;
- CycloneDX XML, SPDX, SBOM import, SBOM diff, VEX, signing, or attestation;
- a headless scanner CLI, CI task, PR annotation, or centralized server; or
- unattended dependency modification.

Those omissions are explicit evidence gaps, not implied negative findings.

## Reporting security issues

Use the repository's private security-reporting facility when available. If it
is not available, open a minimal issue that contains no exploit details or
secrets and request a private contact channel:

https://github.com/brahimkedjar/scan_vulnirabilities/issues
