import type {
  RemediationConfidence as Confidence,
  RemediationStrategy,
} from "./RemediationModels";

export interface RemediationConfidenceInput {
  readonly strategy: RemediationStrategy;
  readonly exactResolvedIdentity: boolean;
  readonly coverageComplete: boolean;
  readonly providerEvidenceComplete: boolean;
}

export function remediationConfidence(
  input: RemediationConfidenceInput,
): Confidence {
  if (
    input.strategy === "unresolved" ||
    input.strategy === "no-fixed-version" ||
    input.strategy === "manual-review" ||
    !input.exactResolvedIdentity ||
    !input.providerEvidenceComplete
  ) {
    return "low";
  }
  if (
    input.strategy === "upgrade-direct" &&
    input.coverageComplete
  ) {
    return "high";
  }
  return "medium";
}
