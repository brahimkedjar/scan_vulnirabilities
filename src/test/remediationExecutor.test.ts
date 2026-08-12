import { strict as assert } from "node:assert";
import { test } from "node:test";

import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { RemediationRecommendation } from "../remediation/RemediationModels";
import type { FileIdentity, RemediationFileInspection } from "../remediation/apply/FileSnapshot";
import { sha256 } from "../remediation/apply/FileSnapshot";
import {
  type RemediationApplyGuard,
  RemediationExecutor,
  type RemediationScanVerifier,
} from "../remediation/apply/RemediationExecutor";
import { RemediationHistory } from "../remediation/apply/RemediationHistory";
import type { RemediationPlan } from "../remediation/apply/RemediationPlan";
import type { RemediationFileSystem } from "../remediation/apply/RemediationRollback";
import { RemediationValidator } from "../remediation/apply/RemediationValidator";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function uri(path: string, scheme = "file"): vscode.Uri {
  return {
    scheme,
    path,
    fsPath: path,
    toString: () => `${scheme}://${path}`,
  } as unknown as vscode.Uri;
}

const packageUri = uri("/workspace/package.json");

function dependency(version = "4.17.20"): Dependency {
  return {
    name: "lodash",
    ecosystem: "npm",
    requestedVersion: `^${version}`,
    installedVersion: version,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["fixture", `lodash@${version}`],
    manifestPath: "/workspace/package.json",
    packageManager: "npm",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  };
}

function vulnerability(version = "4.17.20"): Vulnerability {
  return {
    id: "GHSA-target",
    aliases: [],
    packageName: "lodash",
    ecosystem: "npm",
    installedVersion: version,
    severity: "HIGH",
    summary: "fixture",
    fixedVersions: ["4.17.21"],
    remediationCandidates: ["4.17.21"],
    fixedVersion: "4.17.21",
    references: [],
    source: "OSV",
  };
}

function scan(version: string, vulnerable: boolean, complete = true): ScanResult {
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: 1,
    vulnerableDependencies: vulnerable ? 1 : 0,
    vulnerabilities: vulnerable ? [vulnerability(version)] : [],
    dependencies: [dependency(version)],
    errors: [],
    providerResults: [
      {
        provider: "OSV",
        status: complete ? "available" : "partial",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: complete ? 1 : 0,
        failed: complete ? 0 : 1,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: vulnerable ? 1 : 0,
      },
    ],
    cancelled: false,
  };
}

function recommendation(): RemediationRecommendation {
  return {
    recommendationKey: "recommendation-1",
    vulnerabilityId: "GHSA-target",
    vulnerabilityIds: ["GHSA-target"],
    dependency: dependency(),
    currentVersion: "4.17.20",
    recommendedVersion: "4.17.21",
    fixedVersions: ["4.17.21"],
    strategy: "upgrade-direct",
    confidence: "high",
    dependencyPath: ["fixture", "lodash@4.17.20"],
    directDependency: true,
    breakingChangeRisk: "low",
    reason: "fixture",
    evidence: [],
  };
}

function plan(before: Uint8Array, afterText: string): RemediationPlan {
  const after = encoder.encode(afterText);
  return {
    id: "plan-1",
    recommendationKey: "recommendation-1",
    recommendation: recommendation(),
    capability: "safe",
    files: [
      {
        uri: packageUri,
        operation: "modify",
        beforeHash: sha256(before),
        afterHash: sha256(after),
        afterContent: afterText,
        description: "Minimal range-preserving remediation.",
      },
    ],
    warnings: [],
    validationSteps: [
      { kind: "file-format", description: "Validate JSON", required: true },
      { kind: "rescan", description: "Rescan", required: true },
    ],
    expectedOutcome: {
      packageName: "lodash",
      fromVersion: "4.17.20",
      toVersion: "4.17.21",
      targetedVulnerabilityIds: ["GHSA-target"],
      expectedAddressed: 1,
      requiresCompleteCoverage: true,
    },
    reasonCode: "safe-npm-existing-resolution",
  };
}

interface MemoryEntry {
  bytes: Uint8Array;
  identity: number;
  kind: RemediationFileInspection["kind"];
  writable: boolean;
  reparsePoint: boolean;
}

class MemoryFileSystem implements RemediationFileSystem {
  public readonly entries = new Map<string, MemoryEntry>();
  public replacements = 0;
  public corruptReplacement = -1;
  public throwAfterReplacement = -1;
  public failInspectionAfterReplacement = false;
  public atomicReplaceAvailable = true;
  public mutateInPlaceBeforeReplacement = -1;
  public inPlaceMutationText = '{"user":"in-place change"}\n';

  public constructor(initial: Uint8Array) {
    this.entries.set(packageUri.toString(), {
      bytes: new Uint8Array(initial),
      identity: 1,
      kind: "file",
      writable: true,
      reparsePoint: false,
    });
  }

  public async inspect(target: vscode.Uri): Promise<RemediationFileInspection> {
    if (this.failInspectionAfterReplacement && this.replacements > 0) {
      throw new Error("post-replacement inspection unavailable");
    }
    const entry = this.entry(target);
    return {
      kind: entry.kind,
      size: entry.bytes.byteLength,
      writable: entry.writable,
      reparsePoint: entry.reparsePoint,
      identity: { value: entry.identity.toString() },
      canonicalPath: target.fsPath,
      mode: entry.writable ? 0o644 : 0o444,
    };
  }

  public async readFile(target: vscode.Uri): Promise<Uint8Array> {
    return new Uint8Array(this.entry(target).bytes);
  }

  public canGuaranteeAtomicReplace(_target: vscode.Uri): boolean {
    return this.atomicReplaceAvailable;
  }

  public async replaceFileAtomic(
    target: vscode.Uri,
    bytes: Uint8Array,
    expectedIdentity: FileIdentity,
    expectedHash: string,
  ): Promise<RemediationFileInspection> {
    const entry = this.entry(target);
    const replacementNumber = this.replacements + 1;
    if (replacementNumber === this.mutateInPlaceBeforeReplacement) {
      // Model an external write through the same inode after the executor's
      // read/hash check but before the adapter's atomic compare-and-swap.
      entry.bytes = encoder.encode(this.inPlaceMutationText);
    }
    if (
      entry.identity.toString() !== expectedIdentity.value ||
      sha256(entry.bytes) !== expectedHash ||
      entry.kind !== "file" ||
      entry.reparsePoint
    ) {
      throw new Error("identity or content changed");
    }
    this.replacements = replacementNumber;
    entry.bytes =
      this.replacements === this.corruptReplacement
        ? encoder.encode("corrupt")
        : new Uint8Array(bytes);
    entry.identity += 1;
    if (this.replacements === this.throwAfterReplacement) {
      throw new Error("replacement completed but acknowledgement failed");
    }
    return this.inspect(target);
  }

  public text(): string {
    return decoder.decode(this.entry(packageUri).bytes);
  }

  public externallyWrite(text: string): void {
    const entry = this.entry(packageUri);
    entry.bytes = encoder.encode(text);
    entry.identity += 1;
  }

  private entry(target: vscode.Uri): MemoryEntry {
    const entry = this.entries.get(target.toString());
    if (entry === undefined) {
      throw new Error("missing fixture file");
    }
    return entry;
  }
}

interface ExecutorFixture {
  readonly fileSystem: MemoryFileSystem;
  readonly guard: {
    trusted: boolean;
    dirty: boolean;
    inside: boolean;
    scanning: boolean;
    gitChanged: boolean;
  };
  readonly scanVerifier: RemediationScanVerifier;
  readonly executor: RemediationExecutor;
}

function fixture(
  before: Uint8Array,
  rescan: RemediationScanVerifier["rescan"] = async () => [
    scan("4.17.21", false),
  ],
): ExecutorFixture {
  const fileSystem = new MemoryFileSystem(before);
  const state = {
    trusted: true,
    dirty: false,
    inside: true,
    scanning: false,
    gitChanged: false,
  };
  const guard: RemediationApplyGuard = {
    isWorkspaceTrusted: () => state.trusted,
    isScanInProgress: () => state.scanning,
    isTargetInsideWorkspace: () => state.inside,
    hasUnsavedChanges: () => state.dirty,
    hasUnexpectedGitChanges: () => state.gitChanged,
  };
  const scanVerifier: RemediationScanVerifier = {
    getBeforeResults: () => [scan("4.17.20", true)],
    rescan,
  };
  return {
    fileSystem,
    guard: state,
    scanVerifier,
    executor: new RemediationExecutor({
      fileSystem,
      guard,
      recommendationVerifier: { verifyRecommendation: () => true },
      scanVerifier,
    }),
  };
}

const beforeText = '{\r\n  "dependencies": {\r\n    "lodash": "^4.17.20"\r\n  }\r\n}\r\n';
const afterText = beforeText.replace("^4.17.20", "^4.17.21");

void test("explicit approval is required and bytes remain unchanged", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  const result = await value.executor.execute(plan(before, afterText), {
    approved: false,
  });
  assert.equal(result.status, "refused");
  assert.equal(result.errorCode, "APPROVAL_REQUIRED");
  assert.equal(value.fileSystem.text(), beforeText);
  assert.equal(value.fileSystem.replacements, 0);
});

void test("executor refuses before snapshots or writes without a proven conditional atomic primitive", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.fileSystem.atomicReplaceAvailable = false;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "refused");
  assert.equal(result.errorCode, "ATOMIC_REPLACE_UNAVAILABLE");
  assert.equal(value.fileSystem.replacements, 0);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("read-only Git state blocks modified dependency files without writes", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.guard.gitChanged = true;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "refused");
  assert.equal(result.errorCode, "GIT_STATE_CHANGED");
  assert.equal(value.fileSystem.replacements, 0);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("successful apply validates, rescans, compares, commits, and records history", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "success");
  assert.equal(result.changedFiles, 1);
  assert.equal(result.verification?.comparison.targetedBefore, 1);
  assert.equal(result.verification?.comparison.targetedAfter, 0);
  assert.equal(result.verification?.comparison.resolved, 1);
  assert.equal(value.fileSystem.text(), afterText);
  assert.equal(value.executor.getHistory().length, 1);
});

void test("a preview hash mismatch refuses without overwriting the user file", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.fileSystem.externallyWrite(beforeText.replace("lodash", "other"));
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "refused");
  assert.equal(result.errorCode, "FILES_CHANGED");
  assert.match(value.fileSystem.text(), /other/u);
  assert.equal(value.fileSystem.replacements, 0);
});

void test("atomic apply CAS preserves an in-place user edit made after revalidation", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.fileSystem.mutateInPlaceBeforeReplacement = 1;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "ROLLBACK_FAILED");
  assert.equal(result.rollback?.verified, false);
  assert.equal(value.fileSystem.text(), value.fileSystem.inPlaceMutationText);
  assert.equal(value.fileSystem.replacements, 0);
});

void test("untrusted, unsaved, escaped, and unsafe URI targets are refused", async () => {
  const before = encoder.encode(beforeText);
  for (const [field, code] of [
    ["trusted", "WORKSPACE_UNTRUSTED"],
    ["dirty", "UNSAVED_CHANGES"],
    ["inside", "WORKSPACE_BOUNDARY"],
  ] as const) {
    const value = fixture(before);
    value.guard[field] = field === "trusted" || field === "inside" ? false : true;
    const result = await value.executor.execute(plan(before, afterText), {
      approved: true,
    });
    assert.equal(result.errorCode, code);
    assert.equal(value.fileSystem.replacements, 0);
  }
  const value = fixture(before);
  const unsafePlan = plan(before, afterText);
  const result = await value.executor.execute(
    {
      ...unsafePlan,
      files: [{ ...unsafePlan.files[0]!, uri: uri("/workspace/package.json", "https") }],
    },
    { approved: true },
  );
  assert.equal(result.errorCode, "UNSAFE_URI");
});

void test("symlinks, reparse points, and read-only targets are refused", async () => {
  const before = encoder.encode(beforeText);
  for (const mutation of [
    (entry: MemoryEntry): void => { entry.kind = "symbolic-link"; },
    (entry: MemoryEntry): void => { entry.reparsePoint = true; },
    (entry: MemoryEntry): void => { entry.writable = false; },
  ]) {
    const value = fixture(before);
    const entry = value.fileSystem.entries.get(packageUri.toString());
    assert.ok(entry !== undefined);
    mutation(entry);
    const result = await value.executor.execute(plan(before, afterText), {
      approved: true,
    });
    assert.ok(
      result.errorCode === "UNSAFE_FILE_TYPE" ||
        result.errorCode === "READ_ONLY_FILE",
    );
    assert.equal(value.fileSystem.replacements, 0);
  }
});

void test("invalid generated metadata is rejected before the first write", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  const result = await value.executor.execute(plan(before, "{invalid"), {
    approved: true,
  });
  assert.equal(result.errorCode, "INVALID_METADATA");
  assert.equal(value.fileSystem.text(), beforeText);
  assert.equal(value.fileSystem.replacements, 0);
});

void test("scan failure rolls back the exact original bytes", async () => {
  const before = new Uint8Array([0xef, 0xbb, 0xbf, ...encoder.encode(beforeText)]);
  const afterWithBom = `\uFEFF${afterText}`;
  const value = fixture(before, async () => {
    throw new Error("provider unavailable");
  });
  const result = await value.executor.execute(plan(before, afterWithBom), {
    approved: true,
  });
  assert.equal(result.errorCode, "RESCAN_FAILED");
  assert.equal(result.rollback?.verified, true);
  assert.equal(sha256(await value.fileSystem.readFile(packageUri)), sha256(before));
});

void test("incomplete validation coverage rolls back", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before, async () => [scan("4.17.21", false, false)]);
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.errorCode, "INCOMPLETE_COVERAGE");
  assert.equal(result.rollback?.verified, true);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("a validation scan that still reports the targeted vulnerability rolls back", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before, async () => [scan("4.17.21", true)]);
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "TARGET_REMAINS");
  assert.equal(result.rollback?.verified, true);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("an unexpected dependency graph change rolls back", async () => {
  const before = encoder.encode(beforeText);
  const extra: Dependency = {
    ...dependency("1.0.0"),
    name: "unexpected",
    manifestName: "unexpected",
    requestedVersion: "1.0.0",
    installedVersion: "1.0.0",
    dependencyPath: ["fixture", "unexpected@1.0.0"],
  };
  const value = fixture(before, async () => {
    const result = scan("4.17.21", false);
    return [{ ...result, dependenciesScanned: 2, dependencies: [...result.dependencies, extra] }];
  });
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "VALIDATION_FAILED");
  assert.equal(result.rollback?.verified, true);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("cancellation during rescan rolls back", async () => {
  const before = encoder.encode(beforeText);
  const controller = new AbortController();
  const value = fixture(before, async () => {
    controller.abort();
    throw new DOMException("cancelled", "AbortError");
  });
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
    signal: controller.signal,
  });
  assert.equal(result.status, "cancelled");
  assert.equal(result.errorCode, "CANCELLED");
  assert.equal(result.rollback?.verified, true);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("external modification after write is never overwritten by rollback", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before, async () => {
    value.fileSystem.externallyWrite('{"user":"change"}\n');
    return [scan("4.17.21", false)];
  });
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.errorCode, "ROLLBACK_FAILED");
  assert.equal(result.rollback?.verified, false);
  assert.equal(value.fileSystem.text(), '{"user":"change"}\n');
});

void test("atomic rollback CAS preserves an in-place user edit made after rollback revalidation", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before, async () => {
    throw new Error("force rollback");
  });
  value.fileSystem.mutateInPlaceBeforeReplacement = 2;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "ROLLBACK_FAILED");
  assert.equal(result.rollback?.attempted, true);
  assert.equal(result.rollback?.verified, false);
  assert.equal(value.fileSystem.text(), value.fileSystem.inPlaceMutationText);
  assert.equal(value.fileSystem.replacements, 1);
});

void test("rollback corruption is reported as critical and never hidden", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before, async () => {
    throw new Error("fail after apply");
  });
  value.fileSystem.corruptReplacement = 2;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.errorCode, "ROLLBACK_FAILED");
  assert.equal(result.rollback?.verified, false);
  assert.match(result.message, /rollback could not be fully verified/iu);
});

void test("a replacement that writes then throws is recovered and rolled back", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.fileSystem.throwAfterReplacement = 1;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.rollback?.attempted, true);
  assert.equal(result.rollback?.verified, true);
  assert.equal(value.fileSystem.text(), beforeText);
});

void test("an indeterminate post-commit adapter failure is always reported as an unverified critical rollback", async () => {
  const before = encoder.encode(beforeText);
  const value = fixture(before);
  value.fileSystem.failInspectionAfterReplacement = true;
  const result = await value.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "ROLLBACK_FAILED");
  assert.equal(result.rollback?.attempted, true);
  assert.equal(result.rollback?.verified, false);
  assert.match(result.message, /inspect the affected file/iu);
  assert.equal(value.fileSystem.text(), afterText);
});

void test("one global apply lock rejects concurrent transactions", async () => {
  const before = encoder.encode(beforeText);
  let release: (() => void) | undefined;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const first = fixture(before, async () => {
    await pending;
    return [scan("4.17.21", false)];
  });
  const second = fixture(before);
  const firstRun = first.executor.execute(plan(before, afterText), { approved: true });
  await new Promise((resolve) => setTimeout(resolve, 0));
  const secondResult = await second.executor.execute(plan(before, afterText), {
    approved: true,
  });
  assert.equal(secondResult.errorCode, "CONCURRENT_REMEDIATION");
  assert.equal(second.fileSystem.replacements, 0);
  release?.();
  await firstRun;
});

void test("session history is bounded and strips control/bidi payloads", () => {
  let count = 0;
  const history = new RemediationHistory({
    maximumRecords: 2,
    createId: () => `id-${(count += 1).toString()}`,
    clock: () => new Date("2026-08-12T00:00:00.000Z"),
  });
  const before = encoder.encode(beforeText);
  const value = plan(before, afterText);
  const malicious = `${value.expectedOutcome.packageName}\u001b[31m\u202E`;
  const maliciousPlan: RemediationPlan = {
    ...value,
    expectedOutcome: { ...value.expectedOutcome, packageName: malicious },
  };
  for (let index = 0; index < 3; index += 1) {
    history.record(maliciousPlan, {
      planId: value.id,
      status: "failed",
      changedFiles: 0,
      message: `failed\u001b[2J-${index.toString()}`,
    });
  }
  const records = history.getAll();
  assert.equal(records.length, 2);
  assert.doesNotMatch(records[0]?.packageName ?? "", /[\u001b\u202e]/u);
  assert.doesNotMatch(records[0]?.message ?? "", /\u001b/u);
});

void test("validator rejects malformed JSON, YAML, TOML, and XML locally", () => {
  const validator = new RemediationValidator();
  const before = encoder.encode(beforeText);
  const value = plan(before, afterText);
  for (const [target, content] of [
    [uri("/workspace/other.json"), "{"],
    [uri("/workspace/other.yaml"), "key: ["],
    [uri("/workspace/other.toml"), "key = ["],
    [uri("/workspace/other.xml"), "<root>"],
  ] as const) {
    assert.throws(() => validator.validate(target, encoder.encode(content), value));
  }
});
