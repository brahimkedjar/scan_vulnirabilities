# Reachability status

Version 0.8.0 does not implement source-code, call-graph, bytecode, or runtime
reachability analysis. Dependency paths prove package relationships only; they
do not prove that a vulnerable function is invoked.

The explainable risk model therefore reports reachability as `UNKNOWN` and
retains its ten possible points as uncertainty. It never rewrites a missing
import or call observation as `NOT_REACHABLE` or `NOT_EXPLOITABLE`.

A future implementation needs separate bounded analyzers for JavaScript,
Python, JVM bytecode, Go, and Rust, explicit language/version support matrices,
confidence levels, cancellation, and fixtures that distinguish confirmed,
likely, not-observed, and unknown evidence. Until those analyzers exist, the
dependency graph remains inventory evidence only.
