# Security history

Security snapshots are immutable scan records that can be compared over time. The history view shows new findings, resolved findings, version changes, KEV changes, license changes, provenance changes, and reachability changes.

Use:
- `dependency-auditor snapshot .`
- `dependency-auditor diff snapshot-a.json snapshot-b.json`
- `dependency-auditor baseline create .`
- `dependency-auditor gate --baseline baseline.json .`