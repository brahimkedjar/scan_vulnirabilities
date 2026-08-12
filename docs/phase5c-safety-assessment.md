# Phase 5C production-remediation safety assessment

Phase 5C production Apply is not enabled. This is a deliberate safe refusal,
not an untested feature flag.

## Proven blocker

The required replacement operation must make one indivisible decision:

1. resolve the already-approved target without following a replaced parent;
2. compare the target's expected file identity;
3. compare the target's exact expected bytes or SHA-256 hash; and
4. replace it only when both comparisons still hold.

The current public Node/VS Code runtime provides path-based rename/replacement
and file-handle reads, but no primitive combining those four conditions. After
the last identity/hash check and before a path-based rename, another process can
modify the same inode or exchange an ancestor. Rechecking after replacement is
too late because the user file may already have been overwritten. Repeating or
moving the check does not remove the final check-to-use gap.

Platform rename variants improve individual properties but do not expose an
expected-identity-plus-content-hash predicate through the current runtime. A
new native adapter would require separate platform/filesystem qualification,
an explicit non-throw-after-commit contract, crash semantics, and the complete
adversarial suite before production enablement.

Therefore `NodeRemediationFileSystem.canGuaranteeAtomicReplace()` returns
literal `false`, and its replacement method inspects and refuses without
creating a stage file or changing the workspace.

## Implemented groundwork

- a strict remediation lifecycle with bounded immutable history, including
  preview, explicit approval, stale/refused states, manual action, and
  post-verification outcomes;
- opaque, expiring, one-use approval records bound to workspace, dependency,
  versions, manifest/lock paths, vulnerability IDs, plan/recommendation hashes,
  and every before/after file hash;
- invalidation on scan, dependency metadata, configuration, workspace, trust,
  and already-active read-only Git-model changes;
- a dedicated Remediation view with real bounded diffs and state-gated actions;
- a verified manual remediation workflow with Copy Patch, Open File, Open Diff,
  and Re-scan actions; no preview action writes project files;
- bounded link/reparse-aware reads and identity/growth checks;
- an injected-adapter transaction contract requiring atomic identity+hash CAS,
  exact-byte rollback, and preservation of external edits;
- immutable post-apply classifications that never convert incomplete coverage
  or provider failure into `FIXED`; and
- rollback when a validation scan still reports any targeted vulnerability.

Git is observational only. The extension does not activate Git, invoke a Git
command, parse or modify `.git`, create commits, change the index, or use SCM
state as write authority. An observed dirty/conflicted state is an additional
refusal. An unavailable SCM model cannot authorize a future write.

## Capability matrix

Production Apply is supported by **no ecosystem** in the current build. npm,
Yarn, pnpm, Bun, Python requirements, Poetry, Pipenv, Maven, Gradle, Cargo, Go
Modules, NuGet, and Composer remain `PREVIEW-ONLY` or `UNSUPPORTED`. The narrow
npm package-lock v3 planner can show a deterministic two-file proposal when all
local graph and provenance checks pass, but it cannot cross the atomic mutation
boundary.

Phase 5C is complete as a verified manual remediation workflow. Production
Apply remains unavailable for every ecosystem until a future host can provide a
proven atomic identity-and-byte compare-and-replace primitive. Phase 6 has not
been started.
