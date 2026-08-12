import type { SupportedOsvEcosystem } from "../vulnerability/EcosystemMapper";
import type { BreakingChangeRisk } from "./RemediationModels";
import {
  compareEcosystemVersions,
  versionMajor,
} from "./VersionRecommendation";

const SEMANTIC_RISK_ECOSYSTEMS: ReadonlySet<SupportedOsvEcosystem> = new Set([
  "npm",
  "crates.io",
  "Go",
  "NuGet",
  "Packagist",
]);

function numericRelease(value: string): readonly number[] | undefined {
  const unprefixed = value.startsWith("v") ? value.slice(1) : value;
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?/u.exec(unprefixed);
  if (match === null) {
    return undefined;
  }
  return [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

export function analyzeVersionRisk(
  ecosystem: SupportedOsvEcosystem,
  currentVersion: string,
  recommendedVersion: string | undefined,
): BreakingChangeRisk {
  if (
    recommendedVersion === undefined ||
    !SEMANTIC_RISK_ECOSYSTEMS.has(ecosystem) ||
    compareEcosystemVersions(ecosystem, currentVersion, recommendedVersion) ===
      undefined
  ) {
    return "unknown";
  }
  const currentMajor = versionMajor(ecosystem, currentVersion);
  const recommendedMajor = versionMajor(ecosystem, recommendedVersion);
  const currentRelease = numericRelease(currentVersion);
  const recommendedRelease = numericRelease(recommendedVersion);
  if (
    currentMajor === undefined ||
    recommendedMajor === undefined ||
    currentRelease === undefined ||
    recommendedRelease === undefined
  ) {
    return "unknown";
  }
  const majorJump = recommendedMajor - currentMajor;
  if (majorJump > 1) {
    return "high";
  }
  if (majorJump === 1) {
    return "medium";
  }
  return currentRelease[1] === recommendedRelease[1] ? "low" : "medium";
}
