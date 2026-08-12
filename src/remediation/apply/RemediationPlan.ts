import type { RemediationRecommendation } from "../RemediationModels";
import type { FileChange } from "./FileChange";

export type RemediationCapability = "safe" | "preview-only" | "unsupported";

export type RemediationPlanReason =
  | "safe-npm-existing-resolution"
  | "requires-package-manager-resolution"
  | "range-semantics-change"
  | "transitive-manual-review"
  | "unsupported-ecosystem"
  | "no-exact-target"
  | "atomic-replace-unavailable"
  | "unsafe-metadata";

export interface ValidationStep {
  readonly kind: "file-format" | "dependency-resolution" | "rescan";
  readonly description: string;
  readonly required: boolean;
}

export interface ExpectedOutcome {
  readonly packageName: string;
  readonly fromVersion: string;
  readonly toVersion?: string;
  readonly targetedVulnerabilityIds: readonly string[];
  readonly expectedAddressed: number;
  readonly requiresCompleteCoverage: boolean;
}

export interface RemediationPlan {
  readonly id: string;
  readonly recommendationKey: string;
  readonly recommendation: RemediationRecommendation;
  readonly capability: RemediationCapability;
  readonly files: readonly FileChange[];
  readonly warnings: readonly string[];
  readonly validationSteps: readonly ValidationStep[];
  readonly expectedOutcome: ExpectedOutcome;
  readonly reasonCode: RemediationPlanReason;
  /** Opaque evidence token; never a registry credential or URL with secrets. */
  readonly registryProvenanceFingerprint?: string;
  /** Scan generation captured by the controller, if available. */
  readonly scanGeneration?: string;
}
