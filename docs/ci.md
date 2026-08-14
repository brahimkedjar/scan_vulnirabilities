# CI and command-line integration

`dependency-auditor` is a read-only security scanner and gate. It never runs package managers, build tools, project scripts, containers, or arbitrary executables.

The repository includes a checked-in GitHub Actions template at
`.github/workflows/phase8-validation.yml`.

## Example usage

- `dependency-auditor scan .`
- `dependency-auditor scan --json .`
- `dependency-auditor scan --sarif .`
- `dependency-auditor gate .`
- `dependency-auditor licenses .`
- `dependency-auditor provenance .`
- `dependency-auditor reachability .`
- `dependency-auditor snapshot .`
- `dependency-auditor diff snapshot-a.json snapshot-b.json`
- `dependency-auditor sbom import file.json`
- `dependency-auditor sbom diff old.json new.json`
- `dependency-auditor container image.tar`

## Exit codes

- `0` pass
- `1` policy violation
- `2` incomplete, unknown, cancelled, offline-without-evidence, or unsupported state
- `3` invalid configuration
- `4` internal scanner error

## GitHub Actions

```yaml
name: dependency-auditor
on: [push, pull_request]
permissions:
  contents: read
jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - run: npm run compile
      - name: Evaluate security gate
        run: node dist/cli/main.js gate . --format json --output audit.json
      - name: Generate SBOM
        run: node dist/cli/main.js scan --sbom --output bom.cdx.json .
      - name: Generate SARIF
        run: node dist/cli/main.js scan --sarif --output audit.sarif .
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: dependency-auditor-results
          path: |
            audit.json
            audit.sarif
            bom.cdx.json
          retention-days: 30
```

The gate step is the decision point: exit `0` passes, `1` is a policy
violation, `2` is an incomplete/unknown state, `3` is invalid configuration,
and `4` is an internal failure. Every nonzero code fails the job. The JSON,
SARIF, and SBOM artifacts are machine-readable and can be uploaded to a
platform that consumes SARIF.

## GitLab CI

```yaml
scan:
  image: node:22
  script:
    - npm ci
    - npm run compile
    - node dist/cli/main.js gate . --format json --offline
```

## Azure DevOps

```yaml
steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '22.x'
  - script: npm ci
  - script: npm run compile
  - script: node dist/cli/main.js gate . --format json --offline
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Scan') {
      steps {
        sh 'npm ci'
        sh 'npm run compile'
        sh 'node dist/cli/main.js gate . --format json --offline'
      }
    }
  }
}
```

## Shell CI

```sh
npm ci
npm run compile
node dist/cli/main.js gate . --format json --output audit.json
node dist/cli/main.js scan --sbom --output bom.cdx.json .
```

## Policy example

```json
{
  "schemaVersion": 1,
  "minimumSeverity": "HIGH",
  "requireKnownExploitedAbsent": true,
  "blockedPackages": ["left-pad"]
}
```

Use it with `dependency-auditor gate --policy policy.json .`.

## Air-gapped gates

`--offline` never makes a network request. Without a local advisory database
the gate exits `2` (incomplete) instead of passing. Supply a validated local
database when a complete offline decision is required:

```sh
dependency-auditor gate . --offline --offline-db advisories.json --format json
```

Retain the gate JSON, SARIF, and SBOM artifacts for at least 30 days when they
support compliance or release records.
