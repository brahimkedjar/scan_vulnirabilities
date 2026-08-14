# CLI reference

The headless scanner exposes `scan`, `gate`, `licenses`, `provenance`, `reachability`, `snapshot`, `diff`, `baseline`, `sbom`, and `container` commands.

Supported options include:
`--severity`, `--production`, `--development`, `--transitive`, `--offline`, `--fail-on`, `--policy`, `--baseline`, `--format`, `--output`, `--timeout`, `--max-dependencies`, `--max-files`, `--max-bytes`, `--no-cache`, `--refresh`, `--workspace`, `--verbose`, and `--quiet`.

The CLI is read-only and fail-closed. Unsupported or incomplete state returns exit code `2`.