# Threat model

## Protected assets

- workspace source, dependency metadata, credentials, and local paths;
- integrity of manifests and lockfiles;
- accuracy of coverage, provider, policy, risk, and export states; and
- VS Code Extension Host availability.

## Untrusted inputs

Workspace files, package names, registry configuration, provider JSON,
advisory text/URLs, cached values, command arguments, webview messages, and
export destinations are treated as untrusted. Parsers and providers enforce
explicit byte, node, record, graph, concurrency, time, and output limits.

## Trust boundaries

- Static adapters read bounded metadata without executing workspace code.
- Only canonical exact public-registry identities become OSV query subjects.
- Network clients require HTTPS, exact hosts, manual redirects, bounded bodies,
  timeouts, retries, validation, and cancellation.
- Policy and export use the latest attempt and unfiltered findings; historical
  retained evidence cannot authorize a pass.
- Export is an explicit user action. A path is accepted only from VS Code's
  native Save dialog; command/webview arguments cannot provide a path or body.
- Webviews retain strict CSP and escaped/bounded provider content.
- Production dependency remediation remains preview-only because a race-safe
  conditional atomic replacement primitive is unavailable.

## Fail-closed outcomes

Provider failure, stale KEV data, unknown reachability, unresolved dependencies,
malformed policy, truncated data, and unsafe output locations remain partial,
unknown, omitted-with-warning, or failed. None is converted to clean, trusted,
not exploitable, or compliant.

## Known limitations

Static workspace analysis cannot observe user/machine package-manager settings,
dynamic build logic, runtime loading, or advisories absent from configured
sources. CycloneDX/SARIF locations are lexical workspace-relative evidence, not
filesystem realpath or signature proof. See the subsystem documents for
additional boundaries.
