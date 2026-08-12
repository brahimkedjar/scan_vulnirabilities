import type { Dependency } from "../models/Dependency";
import type { RemediationStrategy } from "./RemediationModels";

const UNSAFE_DISPLAY_CHARACTERS =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu;

export function remediationDisplayValue(
  value: string,
  maximumLength = 512,
): string {
  const sanitized = value.replace(UNSAFE_DISPLAY_CHARACTERS, "�");
  return sanitized.length <= maximumLength
    ? sanitized
    : `${sanitized.slice(0, Math.max(0, maximumLength - 1))}…`;
}

export interface RemediationReasonInput {
  readonly strategy: RemediationStrategy;
  readonly dependency: Dependency;
  readonly recommendedVersion?: string;
  readonly parent?: Dependency;
  readonly multipleVulnerabilities: boolean;
  readonly conflict?: "provider" | "constraints" | "version" | "incomplete";
}

export function remediationReason(input: RemediationReasonInput): string {
  const packageName = remediationDisplayValue(input.dependency.name);
  switch (input.strategy) {
    case "upgrade-direct":
      return input.multipleVulnerabilities
        ? `The exact provider-listed candidate satisfies every contributing fixed-version requirement for the directly declared dependency ${packageName}.`
        : `A provider-listed fixed version is available and ${packageName} is declared directly.`;
    case "upgrade-parent": {
      const parentName = remediationDisplayValue(
        input.parent?.manifestName ?? input.parent?.name ?? "the direct parent",
      );
      return `The vulnerable package is transitive. ${parentName} is the unambiguous direct dependency on the stored path; review it for a compatible release that resolves the exact remediation candidate.`;
    }
    case "upgrade-transitive":
      return "The vulnerable package is transitive and has an explicit ecosystem-supported resolution point; review that resolution without treating it as a direct declaration.";
    case "no-fixed-version":
      return "No fixed version is currently provided by the configured vulnerability provider.";
    case "unresolved":
      return "The dependency does not have an authoritative resolved version, so a safe upgrade target cannot be calculated.";
    case "manual-review":
      if (input.conflict === "provider") {
        return "Alias-connected provider records disagree about fixed-version evidence, so no remediation candidate can be established safely.";
      }
      if (input.conflict === "constraints") {
        return "No exact provider-listed fixed version is shared by every contributing vulnerability, so no single remediation candidate can be established.";
      }
      if (input.conflict === "version") {
        return "Provider fixed versions are invalid, incomparable, or do not establish a forward upgrade candidate for this ecosystem.";
      }
      if (input.conflict === "incomplete") {
        return "Analysis bounds omitted one or more known constraints for this dependency occurrence, so no remediation candidate is presented.";
      }
      return "The dependency is transitive and no unambiguous direct parent remediation point could be established from the stored dependency graph.";
  }
}
