# Providers and evidence coverage

Dependency discovery, package vulnerability lookup, evidence aggregation, and
exploitation enrichment are separate boundaries.

## Connected provider matrix

| Source | Host | Role | Data sent |
| --- | --- | --- | --- |
| [OSV](https://osv.dev/) | VS Code and online CLI scan | Exact-version package vulnerability lookup | Canonical ecosystem, package name, exact version |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Explicit VS Code Security Gate and CLI `gate` | CVE known-exploitation enrichment | No workspace/package data; fixed public catalog GET |

OSV is the only connected live package vulnerability provider. NVD, GitHub
Advisory Database/GHSA, EPSS, Snyk, vendor feeds, private enterprise feeds, and
OS-package/container advisory feeds are not configured.

An identifier such as CVE or GHSA inside an OSV result does not mean the named
database was independently queried.

## Exact package subjects

The thirteen static adapters map to `npm`, `PyPI`, `Maven`, `crates.io`, `Go`,
`NuGet`, and `Packagist`. A dependency is sent only when static metadata proves
a supported public-package identity and exact installed version. Equal-looking
names in different ecosystems or versions never share a cache/provider result.

Custom registries, local paths, Git sources, dynamic versions, unsupported
protocols, missing selected versions, and ambiguous configuration remain
unresolved or unsupported. Source eligibility is a query-safety decision, not
full artifact provenance.

## OSV semantics

The request is equivalent to:

```json
{
  "package": {
    "ecosystem": "PyPI",
    "name": "requests"
  },
  "version": "2.31.0"
}
```

Responses are bounded, schema-validated, normalized, and matched to the exact
coordinate. Fixed versions come only from provider fixed events; the scanner
does not invent versions. Provider errors and malformed responses never become
empty successful results.

## KEV semantics

A fresh complete catalog and a validated CVE alias are required. Outcomes are:

- `KNOWN_EXPLOITED` for an exact catalog match;
- `NOT_LISTED` only for a validated CVE absent from a fresh complete catalog;
  or
- `UNKNOWN` for missing CVE identity, stale/unavailable/malformed data,
  cancellation, or disabled enrichment.

`NOT_LISTED` means only absence from the consulted CISA catalog. It is not proof
that exploitation is impossible. The CLI `gate` joins KEV evidence through the
same allowlisted HTTPS catalog provider when the scan produced findings.

## Provider-neutral evidence

The intelligence model groups observations only inside one exact coordinate
and retains source, timestamp, freshness, observed values, aliases, conflicts,
confidence reasons, and missing fields. It does not flatten disagreement into
a synthetic consensus. The interface can accept future sources, but an
interface is not a configured provider.

## Cache and failure behavior

The VS Code host can cache bounded validated successes, including empty OSV
answers. A live failure can use an expired success only as visibly stale
fallback; coverage remains incomplete. KEV has a separate cache and stale data
cannot assert `NOT_LISTED`.

The CLI uses an in-memory cache for each process and has no persistent cache.
`--offline-db FILE` loads a validated bounded local advisory database and keeps
the run offline; without it, offline scans stay incomplete. See
[offline.md](offline.md).

## Provider coverage is not universe coverage

A complete result means every eligible subject in the configured static scan
received usable evidence from the connected provider. It does not prove that:

- every project dependency was statically resolvable;
- OSV contains every vulnerability;
- runtime loading or reachability is known;
- a package is trustworthy, correctly licensed, or free of malicious content;
  or
- an image or operating-system package was checked.
