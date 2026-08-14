import assert from "node:assert/strict";
import {
  cp,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { parseCliArguments } from "../cli/args";
import { runCli, type CliIo } from "../cli/main";
import {
  offlineAdvisoryPayloadSha256,
  type OfflineAdvisoryDatabasePayload,
} from "../core/vulnerability";
import type { Vulnerability } from "../models/Vulnerability";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";

const fixture = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "npm",
  "modern-graph",
);

function capture(): { readonly io: CliIo; stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: {
      stdout: (value) => stdout.push(value),
      stderr: (value) => stderr.push(value),
    },
    stdout,
    stderr,
  };
}

async function fixtureCopy(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dependency-auditor-cli-"));
  await cp(fixture, directory, { recursive: true });
  return directory;
}

const clock = { now: () => Date.parse("2026-08-13T00:00:00.000Z") };
const cleanProvider: VulnerabilityProvider = {
  name: "TEST",
  checkPackage: async () => [],
  checkPackages: async () => [],
};

void test("CLI arguments are strict, bounded, and preserve explicit workspace paths", () => {
  const parsed = parseCliArguments([
    "scan",
    "--production",
    "--no-transitive",
    "--timeout=30s",
    "--max-files",
    "123",
    "--workspace",
    "project-a",
    "project-b",
  ]);
  assert.equal(parsed.includeProduction, true);
  assert.equal(parsed.includeDevelopment, false);
  assert.equal(parsed.includeTransitive, false);
  assert.equal(parsed.timeoutMs, 30_000);
  assert.equal(parsed.maximumFiles, 123);
  assert.deepEqual(parsed.workspacePaths, ["project-a", "project-b"]);
  assert.throws(() => parseCliArguments(["scan", "--unknown"]));
  assert.throws(() =>
    parseCliArguments(["scan", "--json", "--sarif"]),
  );
  assert.throws(() =>
    parseCliArguments(["gate", "--policy", "a", "--fail-on", "HIGH"]),
  );
  const offline = parseCliArguments([
    "scan",
    "--offline-db",
    "advisories.json",
  ]);
  assert.equal(offline.offline, true);
  assert.equal(offline.offlineDatabasePath, "advisories.json");
  assert.equal(
    parseCliArguments(["sbom", "diff", "a.json", "b.json"]).subcommand,
    "diff",
  );
});

void test("CLI scan and gate exit codes distinguish complete, violation, and incomplete", async () => {
  const directory = await fixtureCopy();
  try {
    const clean = capture();
    assert.equal(
      await runCli(["scan", "--json", directory], clean.io, {
        provider: cleanProvider,
        clock,
      }),
      0,
    );
    assert.equal(JSON.parse(clean.stdout.join("")).status, "complete");

    const vulnerableProvider: VulnerabilityProvider = {
      name: "TEST",
      checkPackage: async (packageName, ecosystem, version) => {
        if (packageName !== "package-a") return [];
        const finding: Vulnerability = {
          id: "TEST-1",
          aliases: [],
          packageName,
          ecosystem,
          installedVersion: version,
          severity: "HIGH",
          summary: "Deterministic test finding",
          fixedVersions: [],
          remediationCandidates: [],
          references: [],
          source: "TEST",
        };
        return [finding];
      },
      checkPackages: async (dependencies) => {
        const findings = await Promise.all(
          dependencies.map((dependency) =>
            vulnerableProvider.checkPackage(
              dependency.name,
              dependency.ecosystem,
              dependency.installedVersion,
            ),
          ),
        );
        return findings.flat();
      },
    };
    const gate = capture();
    assert.equal(
      await runCli(["gate", "--json", directory], gate.io, {
        provider: vulnerableProvider,
        clock,
      }),
      1,
    );
    assert.equal(JSON.parse(gate.stdout.join("")).gate.status, "FAIL");

    const offline = capture();
    assert.equal(
      await runCli(["gate", "--offline", "--json", directory], offline.io, {
        provider: vulnerableProvider,
        clock,
      }),
      2,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("CLI JSON output is deterministic with injected clock and provider", async () => {
  const directory = await fixtureCopy();
  try {
    const first = capture();
    const second = capture();
    await runCli(["scan", "--json", directory], first.io, {
      provider: cleanProvider,
      clock,
    });
    await runCli(["scan", "--json", directory], second.io, {
      provider: cleanProvider,
      clock,
    });
    assert.equal(first.stdout.join(""), second.stdout.join(""));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("CLI report output never overwrites an existing file", async () => {
  const directory = await fixtureCopy();
  const output = join(directory, "report.json");
  try {
    await writeFile(output, "preserve-me", "utf8");
    const captured = capture();
    assert.equal(
      await runCli(
        ["scan", "--json", "--output", output, directory],
        captured.io,
        { provider: cleanProvider, clock },
      ),
      3,
    );
    assert.equal(await readFile(output, "utf8"), "preserve-me");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("license, provenance, and snapshot commands expose honest evidence", async () => {
  const directory = await fixtureCopy();
  try {
    const licenses = capture();
    assert.equal(
      await runCli(["licenses", "--json", directory], licenses.io, {
        provider: cleanProvider,
        clock,
      }),
      2,
    );
    const licenseOutput = JSON.parse(licenses.stdout.join("")) as {
      readonly inventory: {
        readonly coverage: { readonly unknownLicenseRecords: number };
      };
    };
    assert.equal(licenseOutput.inventory.coverage.unknownLicenseRecords > 0, true);

    const provenance = capture();
    assert.equal(
      await runCli(["provenance", "--json", directory], provenance.io, {
        provider: cleanProvider,
        clock,
      }),
      2,
    );
    assert.equal(
      (JSON.parse(provenance.stdout.join("")) as {
        readonly provenance: { readonly coverage: { readonly unknownRecords: number } };
      }).provenance.coverage.unknownRecords > 0,
      true,
    );

    const snapshotPath = join(directory, "snapshot.json");
    const snapshot = capture();
    assert.equal(
      await runCli(
        ["snapshot", "--json", "--output", snapshotPath, directory],
        snapshot.io,
        { provider: cleanProvider, clock },
      ),
      0,
    );
    assert.equal(
      (JSON.parse(await readFile(snapshotPath, "utf8")) as { readonly schema: string })
        .schema,
      "dependency-auditor/security-snapshot",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("snapshot diff and baseline lifecycle are functional and integrity checked", async () => {
  const directory = await fixtureCopy();
  try {
    const first = join(directory, "snapshot-a.json");
    const second = join(directory, "snapshot-b.json");
    for (const output of [first, second]) {
      assert.equal(
        await runCli(
          ["snapshot", "--output", output, directory],
          capture().io,
          { provider: cleanProvider, clock },
        ),
        0,
      );
    }
    const diff = capture();
    assert.equal(await runCli(["diff", "--json", first, second], diff.io), 0);
    assert.equal(
      (JSON.parse(diff.stdout.join("")) as { readonly complete: boolean }).complete,
      true,
    );

    const baselinePath = join(directory, "baseline.json");
    assert.equal(
      await runCli(
        ["baseline", "create", "--output", baselinePath, directory],
        capture().io,
        { provider: cleanProvider, clock },
      ),
      0,
    );
    const compared = capture();
    assert.equal(
      await runCli(
        ["baseline", "compare", "--json", baselinePath, directory],
        compared.io,
        { provider: cleanProvider, clock },
      ),
      0,
    );
    assert.equal(
      (JSON.parse(compared.stdout.join("")) as { readonly complete: boolean }).complete,
      true,
    );

    await writeFile(first, "{}", "utf8");
    assert.equal(
      await runCli(["diff", first, second], capture().io),
      3,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("CycloneDX import, diff, and merge use bounded canonical operations", async () => {
  const directory = await fixtureCopy();
  try {
    const bomPath = join(directory, "bom.json");
    assert.equal(
      await runCli(
        ["scan", "--sbom", "--output", bomPath, directory],
        capture().io,
        { provider: cleanProvider, clock },
      ),
      0,
    );
    for (const argv of [
      ["sbom", "import", "--json", bomPath],
      ["sbom", "diff", "--json", bomPath, bomPath],
      ["sbom", "merge", "--json", bomPath, bomPath],
    ]) {
      const captured = capture();
      assert.equal(await runCli(argv, captured.io), 0);
      assert.doesNotThrow(() => JSON.parse(captured.stdout.join("")));
    }
    await writeFile(join(directory, "invalid-bom.json"), "[]", "utf8");
    assert.equal(
      await runCli(
        ["sbom", "import", join(directory, "invalid-bom.json")],
        capture().io,
      ),
      3,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("current offline advisory databases are auditable and never call the network provider", async () => {
  const directory = await fixtureCopy();
  try {
    const discovery = capture();
    assert.equal(
      await runCli(["scan", "--json", directory], discovery.io, {
        provider: cleanProvider,
        clock,
      }),
      0,
    );
    const scan = JSON.parse(discovery.stdout.join("")) as {
      readonly results: readonly {
        readonly dependencies: readonly {
          readonly ecosystem: string;
          readonly name: string;
          readonly installedVersion: string;
        }[];
      }[];
    };
    const coordinates = new Map<string, {
      readonly ecosystem: string;
      readonly packageName: string;
      readonly version: string;
      readonly vulnerabilities: readonly Vulnerability[];
    }>();
    for (const dependency of scan.results.flatMap((result) => result.dependencies)) {
      const entry = {
        ecosystem: dependency.ecosystem,
        packageName: dependency.name,
        version: dependency.installedVersion,
        vulnerabilities: Object.freeze([] as Vulnerability[]),
      };
      coordinates.set(JSON.stringify([entry.ecosystem, entry.packageName, entry.version]), entry);
    }
    const payload: OfflineAdvisoryDatabasePayload = {
      schemaVersion: 1,
      provider: "OFFLINE-TEST",
      generatedAt: "2026-08-12T00:00:00.000Z",
      validUntil: "2026-09-01T00:00:00.000Z",
      entries: [...coordinates.values()],
    };
    const databasePath = join(directory, "offline-advisories.json");
    await writeFile(databasePath, JSON.stringify({
      ...payload,
      payloadSha256: offlineAdvisoryPayloadSha256(payload),
    }), "utf8");
    let accidentalNetworkQueries = 0;
    const forbiddenProvider: VulnerabilityProvider = {
      name: "MUST-NOT-RUN",
      checkPackage: async () => {
        accidentalNetworkQueries += 1;
        return [];
      },
      checkPackages: async () => {
        accidentalNetworkQueries += 1;
        return [];
      },
    };
    const captured = capture();
    assert.equal(
      await runCli(
        ["scan", "--offline-db", databasePath, "--json", directory],
        captured.io,
        { provider: forbiddenProvider, clock },
      ),
      0,
    );
    assert.equal(accidentalNetworkQueries, 0);
    const output = JSON.parse(captured.stdout.join("")) as {
      readonly offline: boolean;
      readonly offlineAdvisoryDatabase: {
        readonly source: string;
        readonly ageMs: number;
        readonly validUntil: string;
      };
    };
    assert.equal(output.offline, true);
    assert.equal(output.offlineAdvisoryDatabase.source, "local-file");
    assert.equal(output.offlineAdvisoryDatabase.ageMs, 86_400_000);
    assert.equal(output.offlineAdvisoryDatabase.validUntil, payload.validUntil);

    const incompletePayload: OfflineAdvisoryDatabasePayload = {
      ...payload,
      entries: payload.entries.slice(0, 1),
    };
    await writeFile(databasePath, JSON.stringify({
      ...incompletePayload,
      payloadSha256: offlineAdvisoryPayloadSha256(incompletePayload),
    }), "utf8");
    assert.equal(
      await runCli(
        ["scan", "--offline-db", databasePath, "--json", directory],
        capture().io,
        { provider: forbiddenProvider, clock },
      ),
      2,
    );

    await writeFile(databasePath, JSON.stringify({
      ...payload,
      payloadSha256: "0".repeat(64),
    }), "utf8");
    assert.equal(
      await runCli(
        ["scan", "--offline-db", databasePath, directory],
        capture().io,
        { clock },
      ),
      3,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("reachability can prove a bounded source path and container analysis remains incomplete", async () => {
  const directory = await fixtureCopy();
  try {
    await writeFile(join(directory, "index.js"), "require('package-a');\n", "utf8");
    const provider: VulnerabilityProvider = {
      name: "TEST",
      checkPackage: async (packageName, ecosystem, version) =>
        packageName === "package-a"
          ? [{
              id: "TEST-REACHABLE",
              aliases: [],
              packageName,
              ecosystem,
              installedVersion: version,
              severity: "HIGH",
              summary: "Reachability fixture",
              fixedVersions: [],
              remediationCandidates: [],
              references: [],
              source: "TEST",
            }]
          : [],
      checkPackages: async (dependencies) =>
        (await Promise.all(dependencies.map((dependency) =>
          provider.checkPackage(
            dependency.name,
            dependency.ecosystem,
            dependency.installedVersion,
          ),
        ))).flat(),
    };
    const reachable = capture();
    assert.equal(
      await runCli(["reachability", "--json", directory], reachable.io, {
        provider,
        clock,
      }),
      1,
    );
    assert.equal(
      (JSON.parse(reachable.stdout.join("")) as {
        readonly analysis: {
          readonly findings: readonly { readonly status: string }[];
        };
      }).analysis.findings.some((finding) => finding.status === "REACHABLE"),
      true,
    );

    const archive = join(directory, "empty.tar");
    await writeFile(archive, new Uint8Array(1_024));
    const container = capture();
    assert.equal(
      await runCli(["container", "--json", archive], container.io),
      2,
    );
    const analysis = JSON.parse(container.stdout.join("")) as {
      readonly coverage: { readonly vulnerabilities: string };
    };
    assert.equal(analysis.coverage.vulnerabilities, "not-configured");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("CLI rejects linked evidence and output parent paths", async (context) => {
  const directory = await fixtureCopy();
  const outside = await mkdtemp(join(tmpdir(), "dependency-auditor-cli-outside-"));
  try {
    const policy = join(outside, "policy.json");
    await writeFile(policy, '{"schemaVersion":1,"minimumSeverity":"HIGH"}', "utf8");
    const linkedPolicy = join(directory, "linked-policy.json");
    const linkedParent = join(directory, "linked-output");
    try {
      await symlink(policy, linkedPolicy, "file");
      await symlink(
        outside,
        linkedParent,
        process.platform === "win32" ? "junction" : "dir",
      );
    } catch (error: unknown) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? error.code
          : undefined;
      if (code === "EPERM" || code === "EACCES") {
        context.skip("This host does not permit creating a test link");
        return;
      }
      throw error;
    }
    assert.equal(
      await runCli(
        ["gate", "--policy", linkedPolicy, directory],
        capture().io,
        { provider: cleanProvider, clock },
      ),
      3,
    );
    const linkedOutput = join(linkedParent, "report.json");
    assert.equal(
      await runCli(
        ["scan", "--output", linkedOutput, directory],
        capture().io,
        { provider: cleanProvider, clock },
      ),
      3,
    );
    await assert.rejects(readFile(linkedOutput));
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
