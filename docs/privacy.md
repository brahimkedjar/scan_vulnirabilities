# Privacy and network behavior

Dependency Vulnerability Auditor performs dependency discovery locally by
statically reading bounded workspace metadata. It does not upload source files,
manifest or lockfile contents, dependency graphs, environment variables,
credentials, tokens, or remediation diffs.

## Outbound requests

Network access occurs only as part of a user-initiated scan, an explicitly
enabled automatic scan, an explicit vulnerability-database refresh, or an
explicit **Evaluate Security Gate** action with CISA KEV enrichment enabled.

### OSV package queries

For each eligible exact dependency, the extension sends a request to
`https://api.osv.dev/v1/query` containing only the canonical ecosystem, package
name, and exact version. For example:

```json
{
  "package": {
    "ecosystem": "PyPI",
    "name": "requests"
  },
  "version": "2.31.0"
}
```

These values can reveal that a particular package version is present in the
workspace. Packages that cannot be mapped safely to a supported public registry
are not submitted.

### CISA KEV catalog

The extension downloads the public CISA Known Exploited Vulnerabilities JSON
catalog from the fixed `www.cisa.gov` feed URL with an HTTPS `GET`. The request
contains no package identity, workspace path, dependency data, source content,
or credentials. Matching happens locally against CVE identifiers already in
the normalized OSV result.

## Transport controls

- Provider clients use HTTPS and exact host allowlists.
- Redirects are rejected.
- Requests have time, retry, concurrency, response-size, and cancellation
  limits.
- Provider payloads are validated and normalized before UI, policy, risk, or
  export code consumes them.
- Advisory links are restricted to credential-free HTTPS URLs retained in the
  selected normalized result.

## Local persistence

Successful provider data is cached in VS Code extension `globalState`, subject
to entry-count, entry-size, total-size, and time-to-live limits. Cache keys keep
provider, ecosystem, canonical package name, and exact version separate. The
CISA catalog uses a distinct provider-scoped key. Errors are not stored as
successful empty results.

The extension does not write credentials to files or Git. Remediation previews
and transaction snapshots are bounded and session-local. Current production
remediation remains manual and preview-only, so scanning, intelligence,
policy evaluation, and export analysis do not rewrite dependency files.

## Export privacy

CycloneDX and SARIF generation is local. Exporters accept workspace roots only
to convert observed local paths to safe relative locations. They omit an
occurrence when a safe relative path cannot be established; absolute workspace
paths are not intentionally emitted. Package coordinates, versions, advisory
identifiers, and relative project paths remain potentially sensitive and
should be reviewed before an exported file is shared.

There is no telemetry, account login, GitHub authentication, or Marketplace
token flow in the scan and intelligence pipeline.
