import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  analyzeLicenseInventory,
  type LicenseEvidenceInput,
  type LicensePolicy,
} from "../core/license/LicenseIntelligence";

const POLICY: LicensePolicy = {
  allowedLicenses: ["MIT", "Apache-2.0"],
  deniedLicenses: ["GPL-3.0"],
  reviewRequiredLicenses: ["MPL-2.0"],
  unknownLicense: "review",
};

function dependency(
  overrides: Partial<LicenseEvidenceInput> = {},
): LicenseEvidenceInput {
  return {
    dependencyId: "npm:fixture@1.0.0",
    name: "fixture",
    ecosystem: "npm",
    version: "1.0.0",
    dependencyType: "direct",
    evidenceSource: "packages/app/package-lock.json",
    ...overrides,
  };
}

void test("license inventory normalizes explicit SPDX metadata and applies policy", () => {
  const inventory = analyzeLicenseInventory(
    [
      dependency({ declaredLicense: "mit" }),
      dependency({
        dependencyId: "npm:copyleft@2",
        name: "copyleft",
        declaredLicense: "GPL-3.0",
        dependencyType: "transitive",
        dependencyPath: ["app", "parent", "copyleft"],
      }),
      dependency({
        dependencyId: "npm:choice@3",
        name: "choice",
        declaredLicense: "MIT OR Apache-2.0",
      }),
    ],
    POLICY,
  );

  const byName = new Map(inventory.entries.map((entry) => [entry.name, entry]));
  assert.equal(byName.get("fixture")?.finding.outcome, "ALLOWED");
  assert.deepEqual(byName.get("fixture")?.identifiers, ["MIT"]);
  assert.equal(byName.get("copyleft")?.finding.outcome, "DENIED");
  assert.equal(byName.get("copyleft")?.dependencyType, "transitive");
  assert.deepEqual(byName.get("copyleft")?.dependencyPath, [
    "app",
    "parent",
    "copyleft",
  ]);
  assert.equal(byName.get("choice")?.finding.outcome, "REVIEW_REQUIRED");
  assert.equal(inventory.coverage.knownLicenseRecords, 3);
  assert.equal(inventory.coverage.analysisComplete, true);
});

void test("absent, unsupported, or oversized metadata remains explicitly UNKNOWN", () => {
  const inventory = analyzeLicenseInventory(
    [
      dependency(),
      dependency({
        dependencyId: "npm:custom@1",
        name: "custom",
        declaredLicense: "Made-Up-Permission-1.0",
      }),
      dependency({
        dependencyId: "npm:oversized@1",
        name: "oversized",
        declaredLicense: "M".repeat(300),
      }),
      dependency({
        dependencyId: "npm:unbalanced@1",
        name: "unbalanced",
        declaredLicense: "(MIT OR Apache-2.0",
      }),
    ],
    POLICY,
  );

  assert.ok(
    inventory.entries.every((entry) => entry.detectionStatus === "UNKNOWN"),
  );
  assert.ok(
    inventory.entries.every(
      (entry) => entry.finding.outcome === "REVIEW_REQUIRED",
    ),
  );
  assert.equal(inventory.coverage.unknownLicenseRecords, 4);
});

void test("contradictory policy fails closed without inventing a decision", () => {
  const result = analyzeLicenseInventory(
    [dependency({ declaredLicense: "MIT" })],
    {
      allowedLicenses: ["MIT"],
      deniedLicenses: ["MIT"],
      unknownLicense: "deny",
    },
  );

  assert.equal(result.coverage.policyValid, false);
  assert.equal(result.entries[0]?.finding.outcome, "UNKNOWN");
});

void test("license evidence drops absolute paths, traversal, controls, and bidi text", () => {
  const result = analyzeLicenseInventory(
    [
      dependency({
        dependencyId: "unsafe\u202Eid",
        name: "unsafe\u0000name",
        evidenceSource: "C:\\Users\\secret\\package.json",
        declaredLicense: "MIT\u202Eexe",
        dependencyPath: ["app", "bad\u001b[31m", "dependency"],
      }),
      dependency({
        dependencyId: "second",
        evidenceSource: "../private/package.json",
        declaredLicense: "MIT",
      }),
    ],
    POLICY,
  );

  const second = result.entries.find((entry) => entry.dependencyId === "second");
  assert.equal(second?.evidenceSource, undefined);
  const unsafe = result.entries.find((entry) => entry.dependencyId === "UNKNOWN");
  assert.equal(unsafe?.name, "UNKNOWN");
  assert.equal(unsafe?.evidenceSource, undefined);
  assert.equal(unsafe?.detectionStatus, "UNKNOWN");
  assert.deepEqual(unsafe?.dependencyPath, []);
  assert.doesNotMatch(JSON.stringify(result), /Users|secret|\u001b|\u202e/iu);
});

void test("license analysis is bounded, cancellable, deterministic, and immutable", () => {
  const inputs = [
    dependency({ dependencyId: "z", name: "z", declaredLicense: "MIT" }),
    dependency({ dependencyId: "a", name: "a", declaredLicense: "MIT" }),
  ];
  const first = analyzeLicenseInventory(inputs, POLICY, { maximumRecords: 1 });
  const second = analyzeLicenseInventory(inputs, POLICY, { maximumRecords: 1 });
  assert.deepEqual(first, second);
  assert.equal(first.coverage.truncated, true);
  assert.equal(first.coverage.omittedRecords, 1);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.entries));
  assert.ok(Object.isFrozen(first.entries[0]?.finding));

  const controller = new AbortController();
  controller.abort();
  const cancelled = analyzeLicenseInventory(inputs, POLICY, {
    signal: controller.signal,
  });
  assert.equal(cancelled.coverage.cancelled, true);
  assert.equal(cancelled.coverage.analysisComplete, false);
  assert.deepEqual(cancelled.entries, []);
});
