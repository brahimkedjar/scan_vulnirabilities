import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  isVulnerability,
  isVulnerabilityArray,
} from "../models/validators";

function validVulnerability(): Record<string, unknown> {
  return {
    id: "OSV-TEST-1",
    aliases: ["CVE-2026-0001"],
    packageName: "example-package",
    ecosystem: "npm",
    installedVersion: "1.2.3",
    severity: "HIGH",
    cvssScore: 8.1,
    summary: "A test advisory",
    details: "First line\nSecond line",
    affectedRange: ">=1.0.0 <1.2.4",
    fixedVersions: ["1.2.4"],
    remediationCandidates: ["1.2.4"],
    fixedVersion: "1.2.4",
    references: ["https://security.example.test/advisory#details"],
    published: "2026-08-01T00:00:00Z",
    modified: "2026-08-02T00:00:00Z",
    source: "OSV",
    providerSeverity: "HIGH",
    severityDetails: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      },
    ],
  };
}

void test("accepts bounded normalized vulnerabilities and multiline advisory text", () => {
  const vulnerability = validVulnerability();
  assert.equal(isVulnerability(vulnerability), true);
  assert.equal(isVulnerabilityArray([vulnerability]), true);
  assert.equal(isVulnerabilityArray([]), true);
});

void test("proves remediation candidates against fixed events for the exact coordinate", () => {
  const crossAdvisoryCandidate = {
    ...validVulnerability(),
    remediationCandidates: ["2.0.0"],
  };
  const sameCoordinateEvidence = {
    ...validVulnerability(),
    id: "OSV-TEST-2",
    fixedVersions: ["2.0.0"],
    remediationCandidates: ["2.0.0"],
    fixedVersion: "2.0.0",
  };

  // The standalone validator can only validate shape; the collection owns
  // the cross-advisory evidence invariant.
  assert.equal(isVulnerability(crossAdvisoryCandidate), true);
  assert.equal(isVulnerabilityArray([crossAdvisoryCandidate]), false);
  assert.equal(
    isVulnerabilityArray([
      crossAdvisoryCandidate,
      sameCoordinateEvidence,
    ]),
    true,
  );
  assert.equal(
    isVulnerabilityArray([
      crossAdvisoryCandidate,
      { ...sameCoordinateEvidence, packageName: "different-package" },
    ]),
    false,
  );
  assert.equal(
    isVulnerabilityArray([
      crossAdvisoryCandidate,
      { ...sameCoordinateEvidence, installedVersion: "1.2.2" },
    ]),
    false,
  );
  assert.equal(
    isVulnerabilityArray([
      crossAdvisoryCandidate,
      { ...sameCoordinateEvidence, ecosystem: "PyPI" },
    ]),
    false,
  );
});

void test("rejects unsafe references, corrupt fields, and invalid CVSS values", () => {
  const insecureReference = {
    ...validVulnerability(),
    references: ["http://security.example.test/advisory"],
  };
  const credentialedReference = {
    ...validVulnerability(),
    references: ["https://user:secret@security.example.test/advisory"],
  };
  const invalidScore = { ...validVulnerability(), cvssScore: Number.NaN };
  const missingIdentity = { ...validVulnerability(), id: undefined };
  const legacyMissingFixedEvidence = {
    ...validVulnerability(),
    fixedVersions: undefined,
  };
  const inconsistentFixedEvidence = {
    ...validVulnerability(),
    fixedVersions: ["1.2.5"],
  };
  const legacyMissingRemediationCandidates = {
    ...validVulnerability(),
    remediationCandidates: undefined,
  };
  const invalidFixedConflict = {
    ...validVulnerability(),
    fixedVersionConflict: "yes",
  };

  assert.equal(isVulnerability(insecureReference), false);
  assert.equal(isVulnerability(credentialedReference), false);
  assert.equal(isVulnerability(invalidScore), false);
  assert.equal(isVulnerability(missingIdentity), false);
  assert.equal(isVulnerability(legacyMissingFixedEvidence), false);
  assert.equal(isVulnerability(inconsistentFixedEvidence), false);
  assert.equal(isVulnerability(legacyMissingRemediationCandidates), false);
  assert.equal(isVulnerability(invalidFixedConflict), false);
});

void test("rejects oversized vulnerability collections and strings", () => {
  const oversizedAliases = {
    ...validVulnerability(),
    aliases: Array.from({ length: 257 }, (_, index) => `CVE-TEST-${index}`),
  };
  assert.equal(isVulnerability(oversizedAliases), false);
  assert.equal(
    isVulnerabilityArray(
      Array.from({ length: 4_097 }, () => validVulnerability()),
    ),
    false,
  );
});
