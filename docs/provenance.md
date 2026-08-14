# Provenance intelligence

Provenance analysis attempts to identify where a dependency came from and whether the available evidence looks consistent.

Captured evidence can include:
- registry
- repository
- homepage
- source URL
- package URL
- version
- integrity
- publisher or author where available
- download source
- lockfile source
- resolved URL

The engine classifies findings as `SAFE`, `KNOWN`, `SUSPICIOUS`, or `UNKNOWN`.
It does not label a package malicious without sufficient evidence.

Suspicious conditions are evidence-based and bounded, including registry mismatch, source mismatch, local-path or Git replacement of a registry package, integrity inconsistencies, and metadata transitions supported by provider evidence.