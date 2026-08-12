# Remediation intelligence

Remediation intelligence is a local, read-only analysis layer over the latest
stored `ScanResult`. It does not query OSV, run a package manager, execute
project code, or modify a manifest or lockfile. A recommendation is a candidate
derived from fixed-version events already present in normalized provider data;
it is not a guarantee that an upgrade is compatible or that a release is free
of every vulnerability.

## Direct remediation

When a vulnerable package is a safely resolved direct dependency and the
provider reports a usable fixed version, the analyzer can recommend that exact
package version with `upgrade-direct`. It prefers the smallest provider-listed
candidate at or above the installed version and avoids crossing a major version
when a candidate in the current major exists.

The recommendation identifies the current version, provider-listed fixed
versions, selected candidate, dependency path, confidence, compatibility-risk
heuristic, reason, and the evidence used. It never edits the declaration.

## Transitive remediation

A vulnerable transitive package is not presented as a direct manifest edit.
The analyzer preserves the dependency path recorded by the package-manager
adapter. It identifies a parent remediation point only when the stored graph
has one unambiguous direct dependency in the same project and manifest origin.
In that case it recommends reviewing or upgrading that parent to a release that
resolves the exact provider-listed remediation candidate; it never invents a
parent version.

If the path or parent is ambiguous, the result is `manual-review`. Flat or
incomplete ecosystem graphs cannot be reconstructed after the scan.

## Fixed-version selection

Normalized vulnerabilities retain a bounded list of authoritative non-Git OSV
`fixed` events. Selection is ecosystem-aware:

- npm-family packages and crates use strict semantic-version comparison;
- Go versions retain the canonical `v` prefix while their semantic core is
  compared;
- safely comparable release forms for PyPI, Maven, NuGet, and Packagist use
  conservative ecosystem-specific ordering only after normalization has
  established an unambiguous provider candidate; and
- an invalid, ambiguous, unsupported, or incomparable version produces manual
  review instead of a guessed target.

The lowest suitable *proven* candidate in the current compatible branch is preferred.
A higher fixed event is not described as proving every later version safe: OSV
ranges can contain reintroductions and parallel release branches.

## Multiple vulnerabilities

Findings are aggregated per exact dependency occurrence and source origin. The
analyzer emits one recommendation for that occurrence, with all contributing
vulnerability IDs. It selects a target only when one provider-listed candidate
can conservatively satisfy every contributing finding in the chosen branch.
Conflicting alias records, incompatible branches, or an empty intersection
produce `manual-review` with low confidence.

Remediation counts cover the findings stored and displayed for the analyzed
scan. Findings hidden by the configured minimum-severity filter are not silently
claimed as remediated. Historical findings retained after a partial refresh are
shown separately by the security UI and are not included in current remediation
coverage.

## No fixed version

When the provider supplies no fixed event, the strategy is
`no-fixed-version`. The UI says **No known fixed version** and recommends manual
review, a supported upgrade investigation, or replacement. It does not claim
that the newest available release is safe.

## Confidence levels

- **High**: exact resolved identity, authoritative fixed candidate, direct
  declaration, and a clear source path.
- **Medium**: authoritative fixed candidate exists but remediation is transitive
  or some graph context is incomplete.
- **Low**: unresolved or invalid versions, ambiguous/conflicting evidence, no
  fixed event, or no safe remediation point.

Confidence describes the evidence behind the recommendation, not the security
of the resulting application.

## Version-jump risk

Compatibility risk is a non-authoritative heuristic. Patch-only changes are
usually labeled low, minor-line changes medium where the ecosystem semantics
support that distinction, and major-line changes high. Ecosystems or version
forms without sufficiently clear semantics are `unknown`. A higher rating means
more compatibility review may be prudent; it does not assert that a breaking
change exists.

## Limitations

- Recommendations are limited to vulnerability records in the stored scan and
  the configured provider's fixed events.
- A fixed event is evidence for that range boundary, not a universal statement
  about all later releases or all advisories.
- The extension does not resolve a future dependency graph, test compatibility,
  activate build profiles, inspect remote package metadata, or determine a
  future parent dependency version.
- Unresolved dependencies cannot receive a reliable version recommendation.
- Provider failures and incomplete dependency coverage remain visible and never
  become a clean or fully remediable state.
- Analysis itself has no write action. Phase 5B can derive bounded fix previews
  from eligible recommendations, but the packaged production filesystem adapter
  currently classifies every plan as preview-only. See
  `docs/remediation-apply.md` for transaction safeguards and capability limits.
