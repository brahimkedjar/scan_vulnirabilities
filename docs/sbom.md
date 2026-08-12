# CycloneDX and SARIF output

The current reporting slice generates two deterministic JSON formats from the
stored scan result:

- CycloneDX JSON 1.6 software bill of materials; and
- SARIF 2.1.0 dependency-vulnerability results.

Generation is local, bounded, cancellable, and does not contact a provider or
execute a package manager. Export uses the unfiltered normalized finding set
when it is available, independently of the UI severity filter.

After a completed scan, run **Dependency Auditor: Export CycloneDX JSON 1.6**
or **Dependency Auditor: Export SARIF 2.1.0**. Each command obtains its output
URI only from VS Code's native Save dialog. Command arguments cannot supply a
path or file body, cancelling performs no write, and incomplete latest-attempt
coverage remains labeled in the generated document and notification.

## CycloneDX JSON 1.6

The CycloneDX document follows the official
[CycloneDX 1.6 JSON schema](https://cyclonedx.org/schema/bom-1.6.schema.json)
and includes:

- one deduplicated library component per canonical
  ecosystem/package/version coordinate;
- stable component `bom-ref` values and Package URLs (purls);
- bounded, safe workspace-relative occurrence evidence when available;
- dependency relationships only when a static adapter proved the path;
- normalized OSV vulnerability records linked to affected components; and
- separate inventory and vulnerability compositions marked `complete`,
  `incomplete`, or `unknown` from scan coverage.

The exporter never invents a transitive edge from a flat lock format. Multiple
observed occurrences can refer to one canonical component. Unsafe or absolute
locations that cannot be reduced to a safe workspace-relative value are
omitted.

CycloneDX output in this slice does not contain license conclusions, hashes,
digital signatures, attestations, VEX analysis, services, container layers, or
runtime reachability. A stable hash used in a `bom-ref` is an identity aid, not
a package integrity verification or signature.

## SARIF 2.1.0

The SARIF log follows the
[SARIF 2.1.0 standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
and includes:

- a stable rule ID preferring a CVE, then GHSA, then the provider advisory ID;
- one result per safely located package/advisory occurrence;
- severity-to-SARIF-level mapping;
- canonical ecosystem, package, exact version, dependency type, environment,
  provider, fix/range, and CVSS properties when available;
- safe workspace-relative artifact URIs and parser-provided source lines; and
- deterministic partial fingerprints for result correlation.

A transitive finding can point at a direct introducer only when the stored
dependency path proves one unambiguous owner. If no safe workspace-relative
artifact location exists, the occurrence is omitted and the SARIF invocation
contains a warning. An incomplete source scan also produces an unsuccessful
invocation notification so absence of more results is not interpreted as clean
coverage.

## Determinism and limits

Callers provide the CycloneDX timestamp and UUID serial number so repeated
generation from the same scan can be made deterministic. Components,
relationships, vulnerabilities, rules, and results are sorted and deduplicated.

Both exporters validate inputs and enforce hard ceilings on scan results,
dependencies, vulnerabilities, occurrences or results, relationships or rules,
and final output bytes. Lower caller-specific limits are supported. Cancellation
is checked throughout construction.

## Current boundary

This slice does not implement CycloneDX XML, SPDX, SBOM import, SBOM diff,
historical SBOM storage, signing, attestation, upload, or server-side lifecycle
management. It also does not provide a headless scanner CLI or CI task. The
SARIF builder is a report generator over a completed extension scan, not a claim
that a standalone command-line scanner exists.
