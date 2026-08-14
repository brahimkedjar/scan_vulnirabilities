# Reachability analysis

Static reachability analysis is conservative and resource-bounded. It separates:
- `VULNERABLE`
- `VULNERABLE + REACHABLE`
- `VULNERABLE + NOT PROVEN REACHABLE`
- `UNKNOWN`

Current support focuses on safe static inspection of imports, requires, entrypoints, and bounded graph links where the ecosystem makes that practical. When evidence is incomplete, the result stays unknown rather than becoming a false exploitability claim.