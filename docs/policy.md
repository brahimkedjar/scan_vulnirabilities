# Security policy and gates

There are two policy layers. The bounded version 1 vulnerability gate is
connected to VS Code and the CLI. The broader Phase 8 advanced policy engine is
accepted by CLI `gate --policy`, and the CLI supplies generated license,
provenance, and reachability evidence during evaluation; the VS Code extension
does not evaluate advanced policies automatically.

## Connected version 1 gate

The connected schema supports:

```json
{
  "schemaVersion": 1,
  "maxCritical": 0,
  "maxHigh": 0,
  "minimumSeverity": "HIGH",
  "minimumCvss": 7,
  "requireKnownExploitedAbsent": true,
  "allowedEcosystems": ["npm", "PyPI"],
  "blockedPackages": [
    "blocked-in-every-ecosystem",
    { "ecosystem": "npm", "name": "blocked-only-in-npm" }
  ],
  "allowedPackages": [],
  "ignoredAdvisories": [
    {
      "id": "CVE-2099-0001",
      "expiresAt": "2099-12-31T23:59:59Z",
      "reason": "Bounded exception tied to an external review"
    }
  ]
}
```

Unknown fields make the policy invalid. Counts are bounded non-negative
integers. Severity values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, or
`CRITICAL`. CVSS is 0 through 10. Package selectors are exact names, not globs
or regular expressions. A block wins over an allow. Advisory exceptions must
have an RFC 3339 UTC expiry and match an exact finding ID or alias.

### Rule semantics

| Field | Gate failure |
| --- | --- |
| `maxCritical`, `maxHigh` | Non-ignored count exceeds the configured maximum |
| `minimumSeverity` | A finding is at or above the threshold; required unknown severity also fails |
| `minimumCvss` | A finding is at or above the threshold; required unknown CVSS also fails |
| `requireKnownExploitedAbsent` | Known exploited or unknown KEV state; only fresh explicit absence passes |
| `allowedEcosystems` | A resolved dependency is outside a non-empty allowlist |
| `blockedPackages` | A resolved dependency matches a block selector |
| `allowedPackages` | A resolved dependency is outside a non-empty allowlist |

VS Code obtains optional KEV evidence during the explicit Security Gate action.
The CLI `gate` loads the same public CISA KEV catalog through the allowlisted
HTTPS provider when a scan produced findings, so a CLI policy requiring KEV
absence is evaluated with the same fresh-catalog semantics and fails closed
when the catalog cannot be loaded or matched.

The evaluator always uses the latest attempt and prefers unfiltered findings.
It cross-checks provider totals. No scan, incomplete/unavailable/cancelled
coverage, hidden findings, malformed input, limits, cancellation, or required
unknown evidence cannot pass.

## CLI usage

```sh
dependency-auditor gate --fail-on HIGH --format json .
dependency-auditor gate --policy dependency-auditor-policy.json --format json .
```

Without `--policy` or `--fail-on`, CLI `gate` defaults to a HIGH severity
threshold. `--policy` and `--fail-on` cannot be combined. For CI use JSON or
text: those outputs include the gate result. The process exit code remains the
authoritative decision for every format.

| Exit | Meaning |
| ---: | --- |
| 0 | Complete `PASS` |
| 1 | Policy `FAIL` |
| 2 | Incomplete or unknown security state |
| 3 | Invalid policy/configuration |
| 4 | Internal failure |

## Host-neutral advanced policy API

`AdvancedPolicyEngine` can consume explicit license inventories, provenance
analysis, static reachability, known-exploitation records, provider confidence,
and scan data. Its schema can express:

- required complete or percentage coverage;
- known-exploited findings;
- reachable findings at a severity threshold;
- explicit unknown reachability disposition;
- denied/review/unknown license outcomes;
- suspicious/unknown provenance and selected anomaly signals;
- denied dependency type, environment, package manager, or ecosystem; and
- minimum provider confidence.

It retains structured `PASS`, `WARN`, or `FAIL` reasons and resource/cancellation
state. `requireEpssEvidence` always fails with `EPSS_NOT_CONFIGURED` because no
authoritative EPSS provider is connected.

The CLI `gate --policy` accepts this schema and evaluates it with license,
provenance, and reachability evidence generated for the scanned workspace.
Unknown fields still make a policy invalid; no field is silently ignored.

## Meaning of PASS

`PASS` means the configured connected policy passed against complete evidence
available to that evaluation. It is not a certification of application
security, legal compliance, trustworthy provenance, or runtime non-reachability.
