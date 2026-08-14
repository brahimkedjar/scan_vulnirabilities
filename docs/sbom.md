# SBOM support

The platform supports CycloneDX import/export plus bounded diff and merge operations.

Available commands:
- `dependency-auditor sbom import file.json`
- `dependency-auditor sbom diff old.json new.json`
- `dependency-auditor sbom merge a.json b.json`

The diff surface includes dependency adds/removes, version changes, vulnerability changes, license changes, provenance changes, and reachability changes. Parsing is safe and deterministic.