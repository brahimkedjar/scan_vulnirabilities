# Supply-chain signals

The current extension protects package identity and source provenance before a
coordinate is sent to OSV. Workspace-local registry and repository settings,
local/Git/path packages, build extensions, applied Gradle scripts/plugins, and
other unprovable sources fail closed where the static adapters recognize them.
This is source eligibility checking, not malware detection.

Version 0.8.0 was the last release before provenance and anomaly analysis were
implemented. The current 0.9.0 release adds bounded provenance scoring,
evidence-backed anomaly classification, and explicit `UNKNOWN` states for
missing metadata.

The analyzer still does not claim malicious intent without sufficient evidence.
It retains source, retrieval time, exact observed fact, confidence, and a
neutral label such as "potential typosquatting candidate" when evidence is
incomplete. A signal must never authorize an automatic dependency change.
