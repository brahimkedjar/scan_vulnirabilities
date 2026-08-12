# Safe remediation

Safe remediation is an explicit, conservative workflow layered on top of the
stored Remediation Intelligence result. Detecting a vulnerability, scanning,
opening a detail view, and generating a preview never modify project files.

> Dependency Auditor never modifies project files without explicit user
> confirmation.

## Preview and approval

**Review Fix** creates a deterministic plan from the current complete scan and
reads only the bounded target metadata. The preview records SHA-256 hashes,
shows the exact files and a real unified diff, and explains whether the plan is
`SAFE`, `PREVIEW-ONLY`, or `UNSUPPORTED`. Diff content is bounded and stripped
of control, ANSI, and bidirectional-spoofing characters before display. The
native VS Code diff uses in-memory, read-only virtual documents; it does not
create preview files in the project.

Opening, copying, or cancelling a preview is not approval. A future `SAFE` preview can be
applied only through two distinct decisions: the exact-proposal **Approve**
dialog, followed by the final **Apply** confirmation after the plan is rebuilt
and compared. Calling the apply command without a live, approved preview is
refused. Only one remediation transaction can run at a time.

## Verified manual remediation

Because the packaged host cannot prove the required atomic replacement
primitive, the production workflow is manual:

1. scan the workspace;
2. open a remediation recommendation;
3. generate a deterministic preview;
4. inspect the real unified diff and SHA-256 hashes;
5. use **Copy Patch**, **Open File**, or **Open Diff** to apply the change
   manually; and
6. run a fresh scan from the remediation view.

The preview always states that the change has not been applied. Manual actions
copy or display already-generated text and open existing files; they never
write the workspace.

## Transaction and file safety

Immediately before a write, the extension repeats all important checks:

- the workspace is trusted and no dependency scan is in progress;
- the recommendation and complete-scan generation are still current;
- every target is a canonical local `file:` URI inside a workspace folder;
- the target is the same regular, writable file and is not a symbolic link or
  Windows reparse point;
- no target editor has unsaved changes; and
- the current SHA-256 hash still matches the preview.

A changed hash aborts with **Files changed since preview. The remediation was
not applied.** Paths from advisory/provider data are never accepted as write
targets. Boundary checks, canonical paths, file identity checks, and repeated
inspection/read checks defend against traversal, symlink, TOCTOU, and file-swap
attacks.

The transaction engine's injected-adapter tests copy original bytes into an
in-memory snapshot immediately before writing. Snapshots are bounded,
session-only, never logged, and never stored inside the workspace. A supported
adapter must atomically compare identity and the exact expected hash as part of
replacement and must never report a pre-commit failure after committing. The
packaged Node adapter cannot prove that contract and refuses before staging or
writing. The extension does not change permissions automatically.

## Minimal edits and format preservation

Proposed JSON changes use source offsets instead of serializing the entire
document. Unrelated keys retain their order and formatting. Existing UTF-8 BOM
and LF/CRLF newline style are retained. A plan is refused when a safe minimal
edit cannot be established. Explicit file-count, per-file, total-snapshot, and
diff limits prevent an untrusted project from causing unbounded memory use.

## Validation and rescan

Generated npm metadata is parsed before any write. After each write it is read
back, hashed, structurally validated, and reconciled with the existing bounded
npm dependency parser. The extension then invokes the existing scanner through
a non-publishing validation path. This is the only network-capable step, and it
uses the existing provider/cache policy; remediation adds no registry or
advisory service.

A successful outcome requires all of the following:

1. every controlled write and read-back check succeeds;
2. the manifest and lock graph remain valid and resolve the exact target;
3. the validation scan completes with acceptable coverage; and
4. the targeted advisory count is compared with the actual post-change scan.

If any targeted finding remains, verification fails and exact-byte rollback is
required. A changed manifest alone is never reported as a successful fix. A
transient post-write scan is published only after transaction validation
succeeds.

## Rollback

Cancellation after writes begin, local validation failure, scan/provider
failure, incomplete coverage, unexpected write failure, or an unresolved target
causes rollback. Only files proven to have been written by the active
transaction are restored. Restoration uses the exact original bytes—not a
reconstructed JSON object—and verifies each restored SHA-256 hash.

If file identity or bytes indicate an external user change, the extension does
not overwrite that change. If rollback cannot be verified, it emits a critical
warning instructing the user to inspect the affected files. Session history
stores only bounded package/version/result summaries and never file content,
credentials, registry URLs, or snapshots.

## Supported remediation capabilities

Detection support does not imply automatic modification support.

| Ecosystem / manager | Current production capability | Notes |
|---|---|---|
| npm | `PREVIEW-ONLY` | A deterministic proposed diff is available for a narrow direct-dependency subset, but packaged production apply is disabled because the current host file primitive cannot prove a race-safe conditional atomic replacement |
| Yarn | `PREVIEW-ONLY` | Yarn is not executed and its lock is not regenerated |
| pnpm | `PREVIEW-ONLY` | pnpm is not executed and its lock is not regenerated |
| Bun | `PREVIEW-ONLY` | Bun is not executed; binary locks remain unsupported |
| Python requirements | `PREVIEW-ONLY` | No lock/environment resolution is inferred |
| Poetry | `PREVIEW-ONLY` | Poetry is not executed and its lock is not regenerated |
| Pipenv | `PREVIEW-ONLY` | Pipenv is not executed and its lock is not regenerated |
| Maven | `PREVIEW-ONLY` | Maven resolution is not executed or guessed |
| Gradle | `PREVIEW-ONLY` | Gradle/build logic is not executed |
| Cargo | `PREVIEW-ONLY` | Cargo is not executed and its lock is not regenerated |
| Go Modules | `PREVIEW-ONLY` | Go commands are not executed |
| NuGet | `PREVIEW-ONLY` | Restore is not executed and lock state is not invented |
| Composer | `PREVIEW-ONLY` | Composer is not executed and its lock is not regenerated |

A recommendation without an exact provider-proven target is `UNSUPPORTED`.
Transitive child versions are never written into a parent declaration, and the
extension never adds a transitive package as a new direct dependency.

## npm lockfile limitations

The extension never manufactures `integrity`, `resolved`, checksum, dependency
graph, or placement data. A normal npm upgrade usually requires npm to resolve
and regenerate the lockfile, so most npm recommendations remain
`PREVIEW-ONLY` with **requires package-manager resolution**. The narrow planning
case can produce a deterministic preview by reusing an artifact already present
in the same lockfile and requires canonical public-registry provenance plus a
complete local graph parse. It still remains `PREVIEW-ONLY` in production
because conditional atomic replacement cannot currently be guaranteed.

No package manager, shell, project script, task, terminal, Git command, or
arbitrary project code is executed. Users may perform a preview-only upgrade
manually with their normal package-management workflow.

## Workspace and format limitations

Applying is unavailable in the packaged host. A future supported adapter must
also refuse untrusted or virtual workspaces, dirty or
read-only targets, for symbolic links/reparse points, and when complete current
scan evidence is unavailable. The extension does not automatically edit YAML, TOML,
XML, line-oriented manifests, or non-npm lockfiles; recognizing those formats
for scanning does not establish safe write semantics.
