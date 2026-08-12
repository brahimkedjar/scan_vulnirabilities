export type ApplyErrorCode =
  | "APPROVAL_REQUIRED"
  | "PREVIEW_REQUIRED"
  | "CAPABILITY_NOT_SAFE"
  | "WORKSPACE_UNTRUSTED"
  | "WORKSPACE_BOUNDARY"
  | "UNSAFE_URI"
  | "UNSAFE_FILE_TYPE"
  | "READ_ONLY_FILE"
  | "ATOMIC_REPLACE_UNAVAILABLE"
  | "UNSAVED_CHANGES"
  | "GIT_STATE_CHANGED"
  | "FILES_CHANGED"
  | "STALE_RECOMMENDATION"
  | "REGISTRY_PROVENANCE_CHANGED"
  | "SCAN_IN_PROGRESS"
  | "CONCURRENT_REMEDIATION"
  | "RESOURCE_LIMIT"
  | "INVALID_METADATA"
  | "VALIDATION_FAILED"
  | "RESCAN_FAILED"
  | "INCOMPLETE_COVERAGE"
  | "TARGET_REMAINS"
  | "CANCELLED"
  | "WRITE_FAILED"
  | "ROLLBACK_FAILED"
  | "UNEXPECTED";

const PUBLIC_MESSAGES: Readonly<Record<ApplyErrorCode, string>> = {
  APPROVAL_REQUIRED: "Apply this dependency remediation only after explicit approval.",
  PREVIEW_REQUIRED: "Create a remediation preview before applying a fix.",
  CAPABILITY_NOT_SAFE: "This remediation cannot be applied automatically.",
  WORKSPACE_UNTRUSTED: "Remediation requires a trusted workspace.",
  WORKSPACE_BOUNDARY: "Remediation refused because a target is outside the trusted workspace.",
  UNSAFE_URI: "Remediation only supports local workspace files.",
  UNSAFE_FILE_TYPE: "Remediation refused because the target file is not a regular file.",
  READ_ONLY_FILE: "A remediation target is read-only.",
  ATOMIC_REPLACE_UNAVAILABLE:
    "Automatic remediation is unavailable because this host cannot guarantee a race-safe atomic file replacement.",
  UNSAVED_CHANGES: "Save or discard your unsaved changes before applying this remediation.",
  GIT_STATE_CHANGED:
    "Dependency files have changed since the remediation was generated. Run a fresh scan before applying.",
  FILES_CHANGED: "Files changed since preview. The remediation was not applied.",
  STALE_RECOMMENDATION: "The remediation recommendation is no longer current.",
  REGISTRY_PROVENANCE_CHANGED: "npm registry provenance changed since the preview.",
  SCAN_IN_PROGRESS: "Wait for the active dependency scan to finish before applying remediation.",
  CONCURRENT_REMEDIATION: "Another remediation operation is already in progress.",
  RESOURCE_LIMIT: "The remediation exceeds a configured safety limit.",
  INVALID_METADATA: "Dependency metadata is malformed or unsupported for safe remediation.",
  VALIDATION_FAILED: "Modified dependency metadata failed validation.",
  RESCAN_FAILED: "The validation scan failed.",
  INCOMPLETE_COVERAGE: "The validation scan did not provide complete coverage.",
  TARGET_REMAINS: "The targeted vulnerability remains after remediation.",
  CANCELLED: "The remediation was cancelled.",
  WRITE_FAILED: "A dependency metadata file could not be updated safely.",
  ROLLBACK_FAILED: "Remediation failed and rollback could not be fully verified. Please inspect the affected files.",
  UNEXPECTED: "The remediation failed unexpectedly.",
};

export class ApplyError extends Error {
  public constructor(
    public readonly code: ApplyErrorCode,
    message: string = PUBLIC_MESSAGES[code],
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ApplyError";
  }
}

export function publicApplyError(error: unknown): ApplyError {
  return error instanceof ApplyError
    ? error
    : new ApplyError("UNEXPECTED", undefined, { cause: error });
}
