# License intelligence status

License inventory and license policy are not implemented in version 0.8.0.
Current dependency records do not carry authoritative license evidence, so the
CycloneDX exporter omits license fields and the policy engine exposes no license
rule. It does not infer a license from a package name, repository URL, or
advisory text.

A future license subsystem needs provider provenance, SPDX expression parsing,
conflict retention, `UNKNOWN` handling, transitive occurrence mapping, and
explicit organization policy. Any risk category would be a configurable policy
classification, not legal advice.
