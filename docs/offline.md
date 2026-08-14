# Offline mode

`--offline` disables network requests. The scanner then relies on local evidence such as cached provider data, local SBOMs, baseline files, and advisory snapshots.

`--offline-db FILE` loads an integrity-verified, bounded local advisory database; the scan
queries only that local provider and stays fully offline. The report shows the
database source, generation time, age, validity window, and payload SHA-256.

Offline mode never reports a project as safe merely because data is stale. If the data is incomplete, the result remains incomplete.
