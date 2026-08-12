# CI and command-line status

Version 0.8.0 provides local VS Code commands for security-gate evaluation and
SARIF/CycloneDX JSON export. It does not ship a headless scanner CLI, CI task,
GitHub workflow, Azure DevOps task, PR annotation, or exit-code contract.

The current package adapters depend on VS Code URI, workspace filesystem, and
discovery APIs. Reusing only the pure policy/export modules would not constitute
a real workspace scan. A future CLI needs a host-neutral filesystem/discovery
port, versioned validated snapshot input, safe output writer, documented exit
codes, and bundle tests proving that it imports neither VS Code nor executable
process APIs. No package manager or project script should be executed.
