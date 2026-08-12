# Security policy and gate

The security gate is a deterministic, bounded evaluation of the latest scan
attempt and its unfiltered normalized findings. It does not rescan or modify
the workspace. Run **Dependency Auditor: Evaluate Security Gate** from the
Command Palette. With `dependencyAuditor.enableCisaKevEnrichment` enabled, that
explicit action downloads or reuses the public CISA catalog; no package or
workspace data is included in the GET request. Disable the setting to keep
known-exploitation evidence `UNKNOWN` without contacting CISA.

The policy is read from the bounded `dependencyAuditor.securityPolicy` VS Code
setting. The complete structured result and at most 200 reason records are
written to the extension Output Channel; the notification reports the final
`PASS`, `WARN`, or `FAIL` status.

## Policy schema

The first schema version supports this object shape:

```json
{
  "schemaVersion": 1,
  "maxCritical": 0,
  "maxHigh": 2,
  "minimumSeverity": "CRITICAL",
  "minimumCvss": 9,
  "requireKnownExploitedAbsent": true,
  "allowedEcosystems": ["npm", "PyPI"],
  "blockedPackages": [
    "unscoped-name",
    { "ecosystem": "npm", "name": "specific-package" }
  ],
  "allowedPackages": [],
  "ignoredAdvisories": [
    {
      "id": "CVE-2099-0001",
      "expiresAt": "2099-12-31T23:59:59Z",
      "reason": "Time-bounded exception with an external review record"
    }
  ]
}
```

All fields are optional, but unknown fields make the policy invalid. Counts are
bounded non-negative integers. `minimumCvss` is from 0 through 10. Severity is
one of `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

Package-selector strings match an exact canonical package name in every
ecosystem. An object selector scopes the same exact name to one exact canonical
ecosystem. Selectors are not regular expressions or globs. A blocked selector
wins over an allowed selector. When `allowedPackages` is non-empty, every
resolved package outside that allowlist fails.

`ignoredAdvisories` match a finding's canonical ID or alias. Every ignore needs
an RFC 3339 UTC expiration. At the expiration instant the exception no longer
applies and produces a warning reason. The optional reason is descriptive; it
does not change evaluation.

## Rule semantics

| Field | Failure condition |
|---|---|
| `maxCritical` | Non-ignored critical finding count is greater than the value |
| `maxHigh` | Non-ignored high finding count is greater than the value |
| `minimumSeverity` | A non-ignored finding is at or above the threshold |
| `minimumCvss` | A non-ignored finding has CVSS at or above the threshold |
| `requireKnownExploitedAbsent` | A finding is in CISA KEV, or fresh unambiguous exploitation evidence is unavailable |
| `allowedEcosystems` | A resolved package is outside a non-empty ecosystem allowlist |
| `blockedPackages` | A resolved package matches a block selector |
| `allowedPackages` | A resolved package is outside a non-empty package allowlist |

When a severity or CVSS rule requires a value and that value is unknown, the
gate fails because compliance cannot be proven. When
`requireKnownExploitedAbsent` is true, both `KNOWN_EXPLOITED` and `UNKNOWN` fail;
only an exact CVE checked against a fresh, complete KEV catalog can supply the
required `NOT_LISTED` evidence.

## Latest-attempt and unfiltered evidence

The evaluator uses the latest scan attempt, not retained historical display
evidence. It prefers the scan result's unfiltered finding collection so a UI
severity filter cannot hide a blocking vulnerability. Provider finding totals
are cross-checked against the collection available to the evaluator. Missing
provider records fail as hidden evidence; they cannot produce a pass.

The gate fails closed when:

- there is no completed latest scan;
- latest-attempt provider or dependency coverage is partial, unavailable, or
  cancelled;
- the policy or scan input is malformed, duplicated, or over a safety limit;
- evaluation is cancelled;
- a rule needs evidence whose state is unknown; or
- provider totals show findings that are unavailable to evaluation.

## Output

The result contains:

- `PASS`, `WARN`, or `FAIL`;
- a separate `complete` flag;
- scan coverage and cancellation state;
- whether policy validation succeeded;
- bounded structured reason codes and messages; and
- evaluated dependency/finding, ignored, severity, and hidden counts.

`PASS` means the supplied policy passed against complete evidence from that
latest attempt. It is not a certification that the application is secure, that
all vulnerabilities exist in OSV, or that all runtime code paths are reachable.

## Current boundary

Policy is workspace-local extension behavior. There is no organization-wide
policy server, signed policy bundle, PR status check, headless gate CLI, or
license/provenance/container/maintainer-health rule in this slice. No source or
call-graph reachability rule is available.
