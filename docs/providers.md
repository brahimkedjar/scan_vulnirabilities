# Vulnerability and exploitation sources

Dependency Vulnerability Auditor keeps package discovery, vulnerability lookup,
evidence aggregation, and exploitation enrichment as separate trust boundaries.
This document describes the sources that are connected in the current runtime,
not every source that the internal aggregation model could represent.

## Runtime source matrix

| Source | Runtime role | Data sent | Result semantics |
|---|---|---|---|
| [OSV](https://osv.dev/) | Vulnerability lookup for an exact supported package version | Canonical ecosystem, canonical package name, and exact version | Normalized advisory records for the queried coordinate |
| [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploitation enrichment of CVE identifiers already present in normalized findings | Nothing from the workspace; the extension downloads the public catalog with an HTTPS `GET` | `KNOWN_EXPLOITED`, `NOT_LISTED`, or `UNKNOWN` with freshness and reason |

OSV is the only live package vulnerability provider. The extension does not
query NVD or GitHub Advisory Database directly. A CVE or GHSA value appearing in
an OSV alias list is an identifier reported by OSV; it is not evidence that the
extension independently consulted the named database.

## Package coverage

Thirteen static package-manager adapters map to seven canonical OSV ecosystems:

| Canonical ecosystem | Adapters |
|---|---|
| `npm` | npm, Yarn, pnpm, Bun |
| `PyPI` | Python requirements, Poetry, Pipenv |
| `Maven` | Maven, Gradle |
| `crates.io` | Cargo |
| `Go` | Go Modules |
| `NuGet` | NuGet |
| `Packagist` | Composer |

An adapter being present does not make every declaration queryable. A record
reaches OSV only when static workspace metadata proves a safe public-registry
identity and an exact installed version. Unresolved versions, custom sources,
unsupported syntax, and incomplete graphs remain explicit coverage gaps.

## Evidence aggregation

The provider-neutral intelligence model retains each source observation instead
of flattening it into one synthetic advisory. It groups alias-connected
observations only within the same exact package coordinate:

```text
ecosystem + package name + installed version
```

For each canonical finding it retains provider/advisory provenance, aliases,
field-level evidence, source status and freshness, observed values, explicit
conflicts, confidence reasons, and missing-evidence fields. Transitive alias
links can join observations for one coordinate, but an alias can never merge
findings from different packages, ecosystems, or versions.

The current runtime supplies normalized OSV observations to this model. Its
multi-source contract is an extension point, not a claim that NVD, GHSA, Snyk,
or another advisory provider is active.

## CISA KEV matching and freshness

KEV enrichment uses the official public JSON catalog URL on an exact HTTPS host
allowlist. Catalog input is treated as untrusted and is schema-checked, bounded,
normalized, and cached only after successful validation.

A finding is classified as:

- `KNOWN_EXPLOITED` only when a validated CVE identifier exactly matches an
  entry in a fresh catalog;
- `NOT_LISTED` only when the finding has a validated CVE identifier, the entire
  catalog is fresh and available, and none of those CVEs is present; or
- `UNKNOWN` when there is no validated CVE identity, the catalog is stale or
  unavailable, the request is cancelled, or the evidence cannot be validated.

`NOT_LISTED` means only "not present in the fresh catalog consulted." It is not
proof that exploitation is impossible. A stale catalog is never used to assert
absence. The assessment includes the matched CVE entries, freshness, and a
machine-readable reason so UI and policy code do not have to infer meaning from
a label.

## Failure and cache semantics

- Successful OSV responses, including empty responses, can be cached. Provider
  errors are not cached as a clean result.
- A stale successful OSV result may be displayed only as an explicitly counted
  fallback; coverage remains incomplete.
- A successfully validated KEV catalog can be cached. A stale KEV catalog can
  explain why enrichment is unavailable, but it cannot produce `NOT_LISTED`.
- Cancellation and resource limits do not produce a pass, clean result, or
  synthetic evidence.

See [privacy.md](privacy.md) for network payloads and [security.md](security.md)
for trust boundaries and input limits.
