# Supply-chain signals

The current extension protects package identity and source provenance before a
coordinate is sent to OSV. Workspace-local registry and repository settings,
local/Git/path packages, build extensions, applied Gradle scripts/plugins, and
other unprovable sources fail closed where the static adapters recognize them.
This is source eligibility checking, not malware detection.

Version 0.8.0 does **not** score maintainer changes, lifecycle-script changes,
package popularity, release timing, binary payloads, repository activity,
typosquatting, SLSA attestations, Sigstore signatures, or ownership. It has no
trusted historical registry snapshot from which to derive those facts. Missing
metadata is `UNKNOWN`, not evidence of compromise.

Future signals must retain source, retrieval time, exact observed fact,
confidence, and a neutral label such as “potential typosquatting candidate.” A
signal must never accuse a package or authorize an automatic dependency change.
