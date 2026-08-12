"use strict";

/* eslint-disable @typescript-eslint/no-require-imports -- VS Code loads this test runner through CommonJS. */

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");

const EXTENSION_ID = "brahimkedjar.dependency-vulnerability-auditor";
const COMMANDS = Object.freeze({
  details: "dependencyAuditor.showVulnerabilityDetails",
  refreshDatabase: "dependencyAuditor.refreshVulnerabilityDatabase",
  refreshScan: "dependencyAuditor.refreshScan",
  scan: "dependencyAuditor.scanWorkspace",
  applyFix: "dependencyAuditor.applyFix",
  cancelRemediation: "dependencyAuditor.cancelRemediation",
  previewFix: "dependencyAuditor.previewFix",
  showDashboard: "dependencyAuditor.showDashboard",
  showRemediation: "dependencyAuditor.showRemediation",
  showVulnerabilities: "dependencyAuditor.showVulnerabilities",
});
const EXPECTED_ECOSYSTEM_LABELS = Object.freeze([
  "npm",
  "Python",
  "Maven",
  "Cargo",
  "Go",
  "NuGet",
  "Composer",
]);
const EXPECTED_IDENTITIES = new Set([
  JSON.stringify(["npm", "fixture-npm", "1.2.3"]),
  JSON.stringify(["PyPI", "requests", "2.31.0"]),
  JSON.stringify(["Maven", "org.apache.commons:commons-text", "1.9"]),
  JSON.stringify(["crates.io", "serde", "1.0.210"]),
  JSON.stringify(["Go", "github.com/gin-gonic/gin", "v1.10.0"]),
  JSON.stringify(["NuGet", "Newtonsoft.Json", "13.0.3"]),
  JSON.stringify(["Packagist", "symfony/http-foundation", "v6.4.12"]),
]);
const MOCK_VULNERABILITY_ID = "GHSA-aaaa-bbbb-cccc";

function requiredEnvironment(name) {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
}

function isWithin(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return (
    relative.length === 0 ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(predicate, description, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await wait(40);
  }
  throw new Error(`Timed out waiting for ${description}.`);
}

async function withTimeout(promise, description, timeoutMs = 20_000) {
  let handle;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        handle = setTimeout(
          () => reject(new Error(`Timed out waiting for ${description}`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    clearTimeout(handle);
  }
}

async function closeNotifications() {
  for (const command of [
    "notifications.clearAll",
    "workbench.action.closeMessages",
  ]) {
    try {
      await vscode.commands.executeCommand(command);
    } catch {
      // Command identifiers vary across VS Code releases; either one is enough.
    }
  }
}

async function executeScanCommand(api, command) {
  const previousTimestamp = api.getSnapshot().latestAttemptTimestamp;
  const pending = Promise.resolve(vscode.commands.executeCommand(command));
  let commandFailure;
  pending.catch((error) => {
    commandFailure = error;
  });
  await waitFor(() => {
    if (commandFailure !== undefined) {
      throw commandFailure;
    }
    const snapshot = api.getSnapshot();
    return (
      !snapshot.scanning &&
      snapshot.latestAttemptTimestamp !== undefined &&
      snapshot.latestAttemptTimestamp !== previousTimestamp
    );
  }, `${command} to publish a completed attempt`);
  await closeNotifications();
  await withTimeout(pending, `${command} command completion`);
  return api.getSnapshot();
}

function headers(values) {
  const normalized = new Map(
    Object.entries(values).map(([name, value]) => [name.toLowerCase(), value]),
  );
  return {
    get(name) {
      return normalized.get(String(name).toLowerCase()) ?? null;
    },
  };
}

function jsonResponse(value, status = 200, extraHeaders = {}) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let consumed = false;
  const responseHeaders = headers({
    "content-length": String(bytes.byteLength),
    "content-type": "application/json; charset=utf-8",
    ...extraHeaders,
  });
  return {
    status,
    headers: responseHeaders,
    body: {
      async cancel() {
        consumed = true;
      },
      getReader() {
        return {
          async cancel() {
            consumed = true;
          },
          releaseLock() {},
          async read() {
            if (consumed) {
              return { done: true };
            }
            consumed = true;
            return { done: false, value: bytes };
          },
        };
      },
    },
  };
}

function deterministicVulnerability(identity) {
  return {
    schema_version: "1.6.0",
    id: MOCK_VULNERABILITY_ID,
    modified: "2026-08-01T00:00:00Z",
    published: "2026-08-01T00:00:00Z",
    summary: "Deterministic Phase 5B extension-host fixture",
    details: "Generated only by the offline smoke-test fetch interceptor.",
    affected: [
      {
        package: {
          ecosystem: identity.ecosystem,
          name: identity.name,
        },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "0" }, { fixed: "1.2.4" }],
          },
        ],
        database_specific: { severity: "HIGH" },
      },
    ],
    references: [
      {
        type: "ADVISORY",
        url: `https://osv.dev/vulnerability/${MOCK_VULNERABILITY_ID}`,
      },
    ],
  };
}

function fixtureFileSnapshot(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    assert.ok(directory, "fixture snapshot directory is required");
    const entries = fs
      .readdirSync(directory, { withFileTypes: true })
      .slice()
      .sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.relative(root, absolutePath).replaceAll("\\", "/");
      const stat = fs.lstatSync(absolutePath);
      assert.equal(
        stat.isSymbolicLink(),
        false,
        `fixture entry must not be a symbolic link: ${relativePath}`,
      );
      if (stat.isDirectory()) {
        files.push({ path: `${relativePath}/`, type: "directory" });
        pending.push(absolutePath);
        continue;
      }
      assert.equal(stat.isFile(), true, `fixture entry must be a file: ${relativePath}`);
      const bytes = fs.readFileSync(absolutePath);
      files.push({
        path: relativePath,
        type: "file",
        bytes: bytes.byteLength,
        sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      });
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path, "en"));
}

function assertFixtureUnchanged(root, before) {
  assert.deepEqual(
    fixtureFileSnapshot(root),
    before,
    "The disposable workspace fixture must remain byte-for-byte unchanged",
  );
}

function fileByteSnapshot(filePath) {
  const bytes = fs.readFileSync(filePath);
  return {
    bytes: bytes.byteLength,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

class ProjectExecutionGuard {
  constructor(extensionRoot) {
    this.extensionRoot = extensionRoot.replaceAll("\\", "/").toLowerCase();
    this.originals = new Map();
    this.vscodeOriginals = new Map();
    this.attempts = [];
  }

  install() {
    for (const method of [
      "exec",
      "execFile",
      "execFileSync",
      "execSync",
      "fork",
      "spawn",
      "spawnSync",
    ]) {
      const original = childProcess[method];
      assert.equal(typeof original, "function");
      this.originals.set(method, original);
      childProcess[method] = (...args) => {
        const executable = String(args[0] ?? "");
        const shellCommand = [executable, ...(Array.isArray(args[1]) ? args[1] : [])]
          .map(String)
          .join(" ");
        const callerStack = (new Error().stack ?? "")
          .split("\n")
          .slice(2)
          .join("\n")
          .replaceAll("\\", "/")
          .toLowerCase();
        if (callerStack.includes(this.extensionRoot)) {
          this.attempts.push({ method, command: shellCommand });
          throw new Error(
            `Phase 5B attempted prohibited process execution through ${method}`,
          );
        }
        return original.apply(childProcess, args);
      };
    }

    this.vscodeOriginals.set("createTerminal", vscode.window.createTerminal);
    vscode.window.createTerminal = (...args) => {
      this.attempts.push({ method: "createTerminal", command: String(args[0] ?? "") });
      throw new Error("Phase 5B attempted prohibited terminal creation");
    };
    this.vscodeOriginals.set("executeTask", vscode.tasks.executeTask);
    vscode.tasks.executeTask = (...args) => {
      this.attempts.push({ method: "executeTask", command: String(args[0]?.name ?? "") });
      throw new Error("Phase 5B attempted prohibited task execution");
    };
    this.vscodeOriginals.set("executeCommand", vscode.commands.executeCommand);
    const executeCommand = vscode.commands.executeCommand;
    vscode.commands.executeCommand = (command, ...args) => {
      if (/(?:^|\.)(?:terminal|task|debug|npm)(?:\.|$)/iu.test(String(command))) {
        this.attempts.push({ method: "executeCommand", command: String(command) });
        throw new Error(`Phase 5B attempted prohibited execution command ${String(command)}`);
      }
      return executeCommand.call(vscode.commands, command, ...args);
    };
  }

  restore() {
    for (const [method, original] of this.originals) {
      childProcess[method] = original;
    }
    this.originals.clear();
    vscode.window.createTerminal = this.vscodeOriginals.get("createTerminal");
    vscode.tasks.executeTask = this.vscodeOriginals.get("executeTask");
    vscode.commands.executeCommand = this.vscodeOriginals.get("executeCommand");
    this.vscodeOriginals.clear();
  }
}

class OsvFetchInterceptor {
  constructor(mode) {
    this.mode = mode;
    this.behavior = "success";
    this.includeFixtureVulnerability = true;
    this.requests = [];
    this.activeHangs = 0;
    this.abortedHangs = 0;
    this.originalFetch = globalThis.fetch;
    assert.equal(typeof this.originalFetch, "function", "VS Code must expose fetch");
    this.forwardFetch = this.originalFetch.bind(globalThis);
  }

  install() {
    globalThis.fetch = this.fetch.bind(this);
  }

  restore() {
    globalThis.fetch = this.originalFetch;
  }

  setBehavior(behavior) {
    this.behavior = behavior;
  }

  setFixtureVulnerability(enabled) {
    this.includeFixtureVulnerability = enabled;
  }

  uniqueIdentityKeys() {
    return new Set(
      this.requests.map((request) =>
        JSON.stringify([
          request.package.ecosystem,
          request.package.name,
          request.version,
        ]),
      ),
    );
  }

  parseRequest(input, init) {
    const url = new URL(String(input));
    assert.equal(url.href, "https://api.osv.dev/v1/query");
    assert.equal(init?.method, "POST");
    assert.equal(init?.redirect, "manual");
    assert.equal(typeof init?.body, "string");
    const body = JSON.parse(init.body);
    assert.ok(body && typeof body === "object" && !Array.isArray(body));
    assert.deepEqual(
      Object.keys(body).sort(),
      body.page_token === undefined
        ? ["package", "version"]
        : ["package", "page_token", "version"],
      "OSV requests must contain only canonical identity, version, and optional pagination",
    );
    assert.ok(body.package && typeof body.package === "object");
    assert.deepEqual(Object.keys(body.package).sort(), ["ecosystem", "name"]);
    assert.equal(typeof body.package.ecosystem, "string");
    assert.equal(typeof body.package.name, "string");
    assert.equal(typeof body.version, "string");
    this.requests.push(body);
    return body;
  }

  async fetch(input, init) {
    const body = this.parseRequest(input, init);
    if (this.mode === "real") {
      return this.forwardFetch(input, init);
    }
    if (this.behavior === "failure") {
      return jsonResponse(
        { error: "deterministic extension-host provider failure" },
        503,
        { "retry-after": "0" },
      );
    }
    if (this.behavior === "hang") {
      this.activeHangs += 1;
      return new Promise((_resolve, reject) => {
        let settled = false;
        const finish = () => {
          if (settled) {
            return;
          }
          settled = true;
          this.activeHangs -= 1;
          this.abortedHangs += 1;
          const error = new Error("deterministic fetch cancellation");
          error.name = "AbortError";
          reject(error);
        };
        if (init?.signal?.aborted === true) {
          finish();
          return;
        }
        init?.signal?.addEventListener("abort", finish, { once: true });
      });
    }

    const identityKey = JSON.stringify([
      body.package.ecosystem,
      body.package.name,
      body.version,
    ]);
    const vulnerableIdentity = JSON.stringify(["npm", "fixture-npm", "1.2.3"]);
    return jsonResponse({
      vulns:
        this.includeFixtureVulnerability && identityKey === vulnerableIdentity
          ? [deterministicVulnerability(body.package)]
          : [],
    });
  }
}

function assertExactIdentitySet(actual, expected = EXPECTED_IDENTITIES) {
  assert.deepEqual(
    [...actual].sort(),
    [...expected].sort(),
    "the provider must receive every and only the canonical fixture identities",
  );
}

function assertStrictCsp(html, surface) {
  assert.equal(typeof html, "string", `${surface} HTML must be rendered`);
  const cspMatch = /http-equiv="Content-Security-Policy" content="([^"]+)"/u.exec(
    html,
  );
  assert.ok(cspMatch, `${surface} must declare a CSP`);
  const csp = cspMatch[1];
  assert.match(csp, /default-src 'none'/u);
  assert.match(csp, /base-uri 'none'/u);
  assert.match(csp, /form-action 'none'/u);
  assert.match(csp, /object-src 'none'/u);
  assert.match(csp, /frame-src 'none'/u);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\bhttps?:/iu);
  const nonceMatch = /style-src 'nonce-([A-Za-z0-9_-]{16,128})'/u.exec(csp);
  assert.ok(nonceMatch, `${surface} style policy must use a strong nonce`);
  const nonce = nonceMatch[1];
  assert.match(csp, new RegExp(`script-src 'nonce-${nonce}'`, "u"));
  assert.ok(html.includes(`<style nonce="${nonce}">`));
  assert.match(
    html,
    new RegExp(`<script nonce="${nonce}" src="[^"]+"></script>`, "u"),
  );
  assert.doesNotMatch(html, /\son[a-z]+\s*=/iu);
}

function flattenTree(nodes) {
  const flattened = [];
  const queue = [...nodes];
  while (queue.length > 0) {
    const node = queue.shift();
    if (!node) {
      continue;
    }
    flattened.push(node);
    if (Array.isArray(node.children)) {
      queue.push(...node.children);
    }
  }
  return flattened;
}

function assertCoverageAndIdentity(snapshot) {
  assert.equal(snapshot.scanning, false);
  assert.equal(snapshot.latestAttemptCoverage, "partial");
  assert.equal(snapshot.latestAttempt.length, 1);
  const result = snapshot.latestAttempt[0];
  assert.equal(result.cancelled, false);
  const coverage = new Map(
    (result.ecosystemCoverage ?? []).map((entry) => [entry.ecosystem, entry]),
  );
  assert.deepEqual(
    [...coverage.keys()].sort(),
    ["Go", "Maven", "NuGet", "Packagist", "PyPI", "crates.io", "npm"].sort(),
  );
  for (const ecosystem of [
    "npm",
    "PyPI",
    "Maven",
    "crates.io",
    "Go",
    "NuGet",
    "Packagist",
  ]) {
    const entry = coverage.get(ecosystem);
    assert.ok(entry, `${ecosystem} coverage must exist`);
    assert.ok(entry.discovered >= 1, `${ecosystem} must discover a dependency`);
    assert.ok(entry.resolved >= 1, `${ecosystem} must resolve a dependency`);
    assert.ok(entry.checked >= 1, `${ecosystem} must check a dependency`);
  }
  assert.ok(coverage.get("PyPI").unresolved >= 1);
  assert.ok(
    result.errors.some((error) => error.code === "DEPENDENCY_UNRESOLVED"),
  );
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_LOCKFILE"),
  );
  const provider = result.providerResults.find((entry) => entry.provider === "OSV");
  assert.ok(provider);
  assert.equal(provider.status, "available");
  assert.equal(provider.failed, 0);
  assert.equal(provider.dependenciesEligible, 7);
  assert.equal(provider.successful, 7);
  const npmFixtureOccurrences = result.dependencies.filter(
    (dependency) =>
      dependency.ecosystem === "npm" &&
      dependency.name === "fixture-npm" &&
      dependency.installedVersion === "1.2.3",
  );
  assert.equal(
    npmFixtureOccurrences.length,
    2,
    "the root and npm workspace manifests must remain distinct dependency origins",
  );
  assert.ok(
    npmFixtureOccurrences.some((dependency) =>
      (dependency.manifestPath ?? dependency.packageJsonPath ?? "")
        .replaceAll("\\", "/")
        .endsWith("/frontend/packages/app/package.json"),
    ),
    "the disposable npm workspace manifest must be represented",
  );
  assert.ok((result.projectCoverage ?? []).length >= 8);
  return result;
}

function assertCompleteCoverageAndIdentity(
  snapshot,
  minimumOccurrences = 2,
  expectedEligible = 1,
) {
  assert.equal(snapshot.scanning, false);
  assert.equal(snapshot.latestAttemptCoverage, "complete");
  assert.equal(snapshot.latestAttempt.length, 1);
  const result = snapshot.latestAttempt[0];
  assert.equal(result.cancelled, false);
  assert.deepEqual(
    (result.ecosystemCoverage ?? []).map((entry) => entry.ecosystem),
    ["npm"],
  );
  const coverage = result.ecosystemCoverage[0];
  assert.ok(coverage.discovered >= minimumOccurrences);
  assert.ok(coverage.resolved >= minimumOccurrences);
  assert.ok(coverage.checked >= minimumOccurrences);
  assert.equal(coverage.unresolved, 0);
  assert.equal(coverage.unsupported, 0);
  assert.equal(result.errors.length, 0);
  const provider = result.providerResults.find((entry) => entry.provider === "OSV");
  assert.ok(provider);
  assert.equal(provider.status, "available");
  assert.equal(provider.failed, 0);
  assert.equal(provider.dependenciesEligible, expectedEligible);
  assert.equal(provider.successful, expectedEligible);
  assert.ok(snapshot.lastSuccessfulResult.length > 0);
  return result;
}

function reportCoverage(result, mode) {
  const lines = (result.ecosystemCoverage ?? [])
    .slice()
    .sort((left, right) => left.ecosystem.localeCompare(right.ecosystem))
    .map(
      (entry) =>
        `${entry.ecosystem}: discovered=${entry.discovered}, resolved=${entry.resolved}, checked=${entry.checked}, vulnerable=${entry.vulnerable}, unresolved=${entry.unresolved}, unsupported=${entry.unsupported}`,
    );
  process.stdout.write(
    `Phase 5B ${mode} provider coverage (disposable fixture):\n${lines
      .map((line) => `  ${line}`)
      .join("\n")}\n`,
  );
}

function dependencyOccurrenceIdentity(dependency) {
  return JSON.stringify([
    dependency.workspacePath ?? "",
    dependency.projectPath ?? "",
    dependency.manifestPath ?? dependency.packageJsonPath ?? "",
    dependency.lockfilePath ?? "",
    dependency.packageManager ?? "",
    dependency.ecosystem,
    dependency.name,
    dependency.installedVersion,
    dependency.resolutionStatus ?? "resolved",
    dependency.dependencyType,
    dependency.dependencyPath ?? [],
  ]);
}

function storedVulnerabilities(snapshot) {
  return snapshot.results.flatMap((result) => result.vulnerabilities);
}

function contributingVulnerabilities(snapshot, recommendation) {
  const identifiers = new Set(recommendation.vulnerabilityIds);
  return storedVulnerabilities(snapshot).filter(
    (vulnerability) =>
      identifiers.has(vulnerability.id) &&
      vulnerability.ecosystem === recommendation.dependency.ecosystem &&
      vulnerability.packageName === recommendation.dependency.name &&
      vulnerability.installedVersion === recommendation.currentVersion,
  );
}

function assertRemediationAnalysis(api, snapshot, interceptor, mode, scenario) {
  const requestCount = interceptor.requests.length;
  const analysis = api.getRemediationAnalysis();
  const repeated = api.getRemediationAnalysis();
  assert.deepEqual(
    repeated,
    analysis,
    "the same stored ScanResult must produce the same remediation analysis",
  );
  assert.equal(
    interceptor.requests.length,
    requestCount,
    "local remediation analysis must not contact OSV",
  );

  const vulnerabilities = storedVulnerabilities(snapshot);
  assert.equal(analysis.summary.totalVulnerabilities, vulnerabilities.length);
  assert.equal(
    analysis.summary.remediationCoveragePercent,
    vulnerabilities.length === 0
      ? 0
      : Math.floor(
          (analysis.summary.remediable * 100) / vulnerabilities.length,
        ),
  );
  assert.equal(
    analysis.summary.analysisComplete,
    scenario !== "partial",
    scenario !== "partial"
      ? "the isolated complete scan must produce complete local remediation analysis"
      : "the fixture's deliberate coverage gaps must keep remediation analysis incomplete",
  );

  const storedDependencies = snapshot.results.flatMap(
    (result) => result.dependencies,
  );
  for (const recommendation of analysis.recommendations) {
    assert.equal(typeof recommendation.recommendationKey, "string");
    assert.ok(recommendation.recommendationKey.length > 0);
    assert.ok(recommendation.vulnerabilityIds.length > 0);
    assert.ok(
      storedDependencies.some(
        (dependency) =>
          dependencyOccurrenceIdentity(dependency) ===
          dependencyOccurrenceIdentity(recommendation.dependency),
      ),
      "each recommendation must retain an exact stored dependency occurrence",
    );
    assert.deepEqual(
      recommendation.dependencyPath,
      recommendation.dependency.dependencyPath ?? [],
      "remediation must preserve the stored dependency path exactly",
    );

    const contributors = contributingVulnerabilities(snapshot, recommendation);
    assert.ok(
      contributors.length > 0,
      "each recommendation must map back to stored vulnerability evidence",
    );
    for (const identifier of recommendation.vulnerabilityIds) {
      assert.ok(
        contributors.some((vulnerability) => vulnerability.id === identifier),
        `stored evidence for ${identifier} is required`,
      );
    }
    for (const vulnerability of contributors) {
      assert.ok(
        Array.isArray(vulnerability.fixedVersions),
        `normalized provider evidence for ${vulnerability.id} must retain fixedVersions`,
      );
      assert.ok(
        Array.isArray(vulnerability.remediationCandidates),
        `normalized provider evidence for ${vulnerability.id} must retain proven remediation candidates`,
      );
    }
    const providerFixedVersions = new Set(
      contributors.flatMap((vulnerability) => vulnerability.fixedVersions),
    );
    for (const fixedVersion of recommendation.fixedVersions) {
      assert.ok(
        providerFixedVersions.has(fixedVersion),
        `remediation fixed version ${fixedVersion} must come from stored provider data`,
      );
    }
    if (recommendation.recommendedVersion !== undefined) {
      assert.ok(
        recommendation.fixedVersions.includes(
          recommendation.recommendedVersion,
        ),
      );
      for (const vulnerability of contributors) {
        assert.ok(
          vulnerability.remediationCandidates.includes(
            recommendation.recommendedVersion,
          ),
          `candidate ${recommendation.recommendedVersion} must be provider-listed and proven unaffected for ${vulnerability.id}`,
        );
        assert.notEqual(
          vulnerability.fixedVersionConflict,
          true,
          "provider-conflicting evidence must never produce a calculated target",
        );
      }
    }
  }

  if (mode === "mock") {
    assert.equal(analysis.summary.totalVulnerabilities, 1);
    assert.equal(analysis.summary.remediable, 1);
    assert.equal(analysis.summary.remediationCoveragePercent, 100);
    assert.ok(analysis.remediable.length >= 1);
    assert.ok(
      analysis.remediable.every(
        (recommendation) => recommendation.recommendedVersion === "1.2.4",
      ),
    );
    assert.ok(
      analysis.remediable.every(
        (recommendation) =>
          recommendation.strategy === "upgrade-direct" &&
          recommendation.directDependency === true &&
          recommendation.breakingChangeRisk === "low" &&
          recommendation.confidence ===
            (scenario === "partial" ? "medium" : "high"),
      ),
      "the deterministic patch candidate must preserve directness and use coverage-aware confidence",
    );
  }
  process.stdout.write(
    `Phase 5B ${mode} remediation provider-equality: displayed=${analysis.summary.totalVulnerabilities}, candidates=${analysis.summary.remediable}, no-fix=${analysis.summary.noKnownFix}, manual=${analysis.summary.manualReview}, unresolved=${analysis.summary.unresolved}\n`,
  );
  return analysis;
}

async function assertShowRemediation(api, interceptor) {
  const before = api.getSnapshot();
  const requestCount = interceptor.requests.length;
  await vscode.commands.executeCommand(COMMANDS.showRemediation);
  await waitFor(
    () => typeof api.getDashboardHtml() === "string",
    "remediation dashboard HTML",
  );
  assert.equal(
    interceptor.requests.length,
    requestCount,
    "Show Remediation must use stored scan data without contacting OSV",
  );
  const after = api.getSnapshot();
  assert.equal(after.latestAttemptTimestamp, before.latestAttemptTimestamp);
  assert.deepEqual(
    after.results,
    before.results,
    "Show Remediation must not rescan or mutate the stored scan result",
  );
  const html = api.getDashboardHtml();
  assertStrictCsp(html, "remediation dashboard");
  assert.match(html, /Remediation/u);
  assert.match(html, /Latest complete scan/u);
  assert.match(html, /Remediation Coverage/u);
  assert.match(html, /This does not mean they are fixed\./u);
  assert.doesNotMatch(
    html,
    /guaranteed fix|definitely safe|fully secure|100% fixed/iu,
  );
  await waitFor(
    () => typeof api.getRemediationCenterHtml() === "string",
    "dedicated remediation center HTML",
  );
  const centerHtml = api.getRemediationCenterHtml();
  assertStrictCsp(centerHtml, "dedicated remediation center");
  assert.match(centerHtml, /<h1>Remediation<\/h1>/u);
  assert.match(centerHtml, /Production Apply is unavailable in this build/u);
  assert.doesNotMatch(centerHtml, /data-remediation-center-action="approve"/u);
  assert.doesNotMatch(centerHtml, /data-remediation-center-action="apply"/u);
  return html;
}

async function assertNoCompleteRemediation(api, interceptor) {
  const before = api.getSnapshot();
  const htmlBefore = api.getDashboardHtml();
  const requestCount = interceptor.requests.length;
  const messages = [];
  const originalShowInformationMessage = vscode.window.showInformationMessage;
  try {
    vscode.window.showInformationMessage = async (message) => {
      messages.push(message);
      return undefined;
    };
    assert.notEqual(
      vscode.window.showInformationMessage,
      originalShowInformationMessage,
      "the extension-host must permit deterministic notification capture",
    );
    await vscode.commands.executeCommand(COMMANDS.showRemediation);
  } finally {
    vscode.window.showInformationMessage = originalShowInformationMessage;
  }
  assert.deepEqual(messages, [
    "No scan results available. Run a dependency scan first.",
  ]);
  assert.equal(interceptor.requests.length, requestCount);
  assert.equal(api.getDashboardHtml(), htmlBefore);
  const after = api.getSnapshot();
  assert.equal(after.latestAttemptTimestamp, before.latestAttemptTimestamp);
  assert.deepEqual(after.results, before.results);
}

function assertTree(api, extensionPath, snapshot, remediationAnalysis, mode) {
  const { buildVulnerabilityTreeModel } = require(
    path.join(extensionPath, "dist", "tree", "treeModel.js"),
  );
  const model = buildVulnerabilityTreeModel(snapshot.results, {
    hasWorkspace: true,
    latestAttemptCoverage: snapshot.latestAttemptCoverage,
    remediationAnalysis,
  });
  assert.equal(model.coverageComplete, false);
  const nodes = flattenTree(model.roots);
  assert.equal(nodes[0]?.label, "Dependency scan coverage is incomplete.");
  const labels = new Set(nodes.map((node) => node.label));
  for (const label of EXPECTED_ECOSYSTEM_LABELS) {
    assert.ok(labels.has(label), `tree must contain the ${label} ecosystem label`);
  }
  for (const workspace of [
    "frontend",
    "backend",
    "maven",
    "cargo",
    "go",
    "nuget",
    "composer",
    "coverage-gap",
  ]) {
    assert.ok(labels.has(`Workspace: ${workspace}`));
  }
  if (mode === "mock") {
    const occurrenceCount = remediationAnalysis.remediable.length;
    if (occurrenceCount === 1) {
      assert.ok(
        [...labels].some((label) => /Recommended upgrade.*1\.2\.4/u.test(label)),
        "tree must expose an unambiguous deterministic remediation candidate",
      );
    } else {
      assert.ok(occurrenceCount > 1);
      assert.ok(
        labels.has("Manual review required"),
        "the grouped tree item must refuse to collapse multiple exact origins into one candidate",
      );
    }
  }
  const apiRootLabels = api.getTreeRootLabels();
  assert.ok(apiRootLabels.includes("Dependency scan coverage is incomplete."));
}

function assertIncompleteStatus(api, expectRemediation = false) {
  const status = api.getStatusModel();
  assert.equal(status.state, "incomplete");
  assert.equal(status.coverageComplete, false);
  assert.ok(status.unresolvedCount >= 1);
  assert.match(status.text, /unresolved|incomplete/iu);
  assert.doesNotMatch(status.text, /secure|no known vulnerabilities/iu);
  assert.match(status.tooltip, /zero findings is not a clean result|coverage is incomplete/iu);
  if (expectRemediation) {
    assert.match(status.text, /1 remediable/u);
    assert.match(status.tooltip, /calculated remediation candidate/iu);
    assert.match(status.tooltip, /no files have been changed/iu);
  }
}

async function assertDashboard(api) {
  await vscode.commands.executeCommand(COMMANDS.showDashboard);
  await waitFor(() => typeof api.getDashboardHtml() === "string", "dashboard HTML");
  const html = api.getDashboardHtml();
  assertStrictCsp(html, "dashboard");
  assert.match(html, /Dependency coverage by ecosystem/u);
  assert.match(html, /Remediation/u);
  assert.match(html, /Remediation Coverage/u);
  assert.match(html, /This does not mean they are fixed\./u);
  assert.match(
    html,
    /Latest scan coverage is incomplete\.|Scan coverage is incomplete\.|Vulnerability database unavailable\./u,
  );
  assert.doesNotMatch(html, /state-success[^>]*>[\s\S]*?No known vulnerabilities were found/iu);
  const filters = [
    ["all", "All"],
    ["npm", "npm"],
    ["PyPI", "Python"],
    ["Maven", "Maven"],
    ["crates.io", "Cargo"],
    ["Go", "Go"],
    ["NuGet", "NuGet"],
    ["Packagist", "Composer"],
  ];
  for (const [key, label] of filters) {
    assert.match(
      html,
      new RegExp(
        `data-ecosystem-filter="${key.replace(".", "\\.")}"[^>]*>${label}<`,
        "u",
      ),
    );
  }
  for (const heading of [
    "Discovered",
    "Resolved",
    "Checked",
    "Unresolved",
    "Unsupported",
    "Coverage",
  ]) {
    assert.match(html, new RegExp(`>${heading}<`, "u"));
  }
  return html;
}

async function assertMockFinding(api, fixtureRoot, interceptor) {
  const snapshot = api.getSnapshot();
  const vulnerability = snapshot.latestAttempt[0]?.vulnerabilities.find(
    (entry) => entry.id === MOCK_VULNERABILITY_ID,
  );
  assert.ok(vulnerability, "mock mode must expose its deterministic npm finding");
  assert.equal(vulnerability.ecosystem, "npm");
  assert.equal(vulnerability.packageName, "fixture-npm");
  assert.deepEqual(vulnerability.fixedVersions, ["1.2.4"]);
  assert.deepEqual(vulnerability.remediationCandidates, ["1.2.4"]);

  const dependency = snapshot.latestAttempt[0].dependencies
    .filter((entry) => {
      const manifestPath = entry.manifestPath ?? entry.packageJsonPath;
      return (
        entry.ecosystem === "npm" &&
        entry.name === "fixture-npm" &&
        entry.installedVersion === "1.2.3" &&
        entry.dependencyType === "direct" &&
        typeof manifestPath === "string" &&
        isWithin(path.resolve(manifestPath), fixtureRoot)
      );
    })
    .sort(
      (left, right) =>
        (left.manifestPath ?? left.packageJsonPath).length -
        (right.manifestPath ?? right.packageJsonPath).length,
    )[0];
  assert.ok(dependency, "exact root npm dependency occurrence is required");
  const dependencyManifestPath =
    dependency.manifestPath ?? dependency.packageJsonPath;
  assert.equal(typeof dependencyManifestPath, "string");
  assert.ok(
    isWithin(
      path.resolve(dependencyManifestPath),
      fixtureRoot,
    ),
    "diagnostic manifest must remain inside the disposable fixture root",
  );

  const manifest = vscode.Uri.file(dependencyManifestPath);
  await waitFor(
    () => vscode.languages.getDiagnostics(manifest).length > 0,
    "npm manifest diagnostic",
  );
  const diagnostics = vscode.languages.getDiagnostics(manifest);
  assert.ok(
    diagnostics.some(
      (diagnostic) =>
        /fixture-npm@1\.2\.3/u.test(diagnostic.message) &&
        /npm dependency/iu.test(diagnostic.message) &&
        /HIGH/u.test(diagnostic.message) &&
        /Known fixed version: 1\.2\.4\./u.test(diagnostic.message) &&
        /Recommended upgrade: 1\.2\.4\./u.test(diagnostic.message),
    ),
    "Problems must include identity, severity, and the exact remediation candidate",
  );

  const requestCount = interceptor.requests.length;
  await vscode.commands.executeCommand(COMMANDS.details, {
    source: vulnerability.source,
    vulnerabilityId: vulnerability.id,
    ecosystem: vulnerability.ecosystem,
    packageName: vulnerability.packageName,
    installedVersion: vulnerability.installedVersion,
    workspacePath: dependency.workspacePath,
    projectPath: dependency.projectPath,
    manifestPath: dependencyManifestPath,
    dependencyPath: dependency.dependencyPath,
  });
  await waitFor(() => typeof api.getDetailsHtml() === "string", "details HTML");
  const details = api.getDetailsHtml();
  assertStrictCsp(details, "vulnerability details");
  assert.match(details, /fixture-npm/u);
  assert.match(details, />npm</u);
  assert.match(details, new RegExp(MOCK_VULNERABILITY_ID, "u"));
  assert.match(details, /<h2 id="remediation-heading">Remediation<\/h2>/u);
  assert.match(details, /Known fixed versions/u);
  assert.match(details, /Remediation candidate/u);
  assert.match(details, /Recommended upgrade/u);
  assert.match(details, /1\.2\.4/u);
  assert.match(details, /Confidence/u);
  assert.match(details, /Dependency path/u);
  assert.match(details, /Evidence/u);
  assert.doesNotMatch(details, /Apply Fix|guaranteed fix|definitely safe/iu);
  assert.equal(
    interceptor.requests.length,
    requestCount,
    "opening remediation details must not contact OSV",
  );
}

async function assertDirectApplyRefused(api, fixtureRoot) {
  const before = fixtureFileSnapshot(fixtureRoot);
  const messages = [];
  const originalInformation = vscode.window.showInformationMessage;
  try {
    vscode.window.showInformationMessage = async (message) => {
      messages.push(String(message));
      return undefined;
    };
    for (const hostileId of ["missing-preview", "../../outside-workspace"]) {
      await vscode.commands.executeCommand(COMMANDS.applyFix, hostileId);
    }
  } finally {
    vscode.window.showInformationMessage = originalInformation;
  }
  assert.ok(
    messages.every((message) => /Create and explicitly approve a remediation preview before applying a fix\./u.test(message)),
    "direct or traversal-shaped apply identifiers must be refused",
  );
  assert.equal(api.getRemediationApplySnapshot().history.length, 0);
  assertFixtureUnchanged(fixtureRoot, before);
}

async function createAndAssertPreviewOnly(api, recommendation, fixtureRoot, interceptor) {
  const before = fixtureFileSnapshot(fixtureRoot);
  const requestCount = interceptor.requests.length;
  await withTimeout(
    Promise.resolve(
      vscode.commands.executeCommand(
        COMMANDS.previewFix,
        recommendation.recommendationKey,
      ),
    ),
    "deterministic remediation preview",
  );
  const snapshot = api.getRemediationApplySnapshot();
  const preview = snapshot.preview;
  assert.ok(preview, "preview command must issue a live preview token");
  assert.equal(preview.recommendationKey, recommendation.recommendationKey);
  assert.equal(preview.capability, "preview-only");
  assert.equal(preview.currentVersion, "1.2.3");
  assert.equal(preview.recommendedVersion, "1.2.4");
  assert.equal(preview.vulnerabilitiesAddressed, 1);
  assert.equal(preview.totalVulnerabilities, 1);
  const lifecycle = snapshot.lifecycles.find(
    (candidate) => candidate.remediationId === preview.id,
  );
  assert.equal(lifecycle?.state, "manualActionRequired");
  assert.equal(preview.files.length, 2);
  assert.ok(
    preview.warnings.some((warning) => /atomic replacement|automatic apply is disabled/iu.test(warning)),
    "the preview must explain why production apply is disabled",
  );
  assert.deepEqual(
    preview.files.map((file) => file.displayPath).sort(),
    ["package-lock.json", "package.json"],
  );
  for (const file of preview.files) {
    assert.match(file.beforeHash, /^[a-f0-9]{64}$/u);
    assert.match(file.afterHash, /^[a-f0-9]{64}$/u);
    assert.notEqual(file.beforeHash, file.afterHash);
    assert.match(file.unifiedDiff, /^--- /mu);
    assert.match(file.unifiedDiff, /^\+\+\+ /mu);
    assert.doesNotMatch(
      file.unifiedDiff,
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u,
    );
  }
  assertFixtureUnchanged(fixtureRoot, before);
  assert.equal(
    interceptor.requests.length,
    requestCount,
    "preview planning and diff generation must not add network requests",
  );
  return preview;
}

async function assertPhase5BRemediation(api, fixtureRoot, interceptor, scenario) {
  assert.equal(scenario, "remediation-preview");
  const originalFixture = fixtureFileSnapshot(fixtureRoot);
  const requestsBeforeRemediation = interceptor.requests.length;
  const analysis = api.getRemediationAnalysis();
  assert.equal(analysis.remediable.length, 1);
  const recommendation = analysis.remediable[0];
  assert.equal(recommendation.strategy, "upgrade-direct");
  assert.equal(recommendation.confidence, "high");
  const declaredCapability = api
    .getRemediationApplySnapshot()
    .capabilities.find(
      (entry) => entry.recommendationKey === recommendation.recommendationKey,
    );
  assert.ok(declaredCapability);
  assert.equal(
    declaredCapability.capability,
    "preview-only",
    "UI capability projection must not advertise SAFE before the production planner proves it",
  );
  await assertDirectApplyRefused(api, fixtureRoot);

  const cancelledPreview = await createAndAssertPreviewOnly(
    api,
    recommendation,
    fixtureRoot,
    interceptor,
  );
  await vscode.commands.executeCommand(COMMANDS.cancelRemediation, cancelledPreview.id);
  assert.equal(api.getRemediationApplySnapshot().preview, undefined);
  assertFixtureUnchanged(fixtureRoot, originalFixture);

  const preview = await createAndAssertPreviewOnly(
    api,
    recommendation,
    fixtureRoot,
    interceptor,
  );
  const messages = [];
  const approvalPrompts = [];
  const originalInformation = vscode.window.showInformationMessage;
  const originalWarning = vscode.window.showWarningMessage;
  try {
    vscode.window.showInformationMessage = async (message) => {
      messages.push(String(message));
      return undefined;
    };
    vscode.window.showWarningMessage = async (message, ...items) => {
      approvalPrompts.push({ message: String(message), items });
      return "Apply Fix";
    };
    for (const id of [preview.id, preview.id, "../../outside-workspace"]) {
      await vscode.commands.executeCommand(COMMANDS.applyFix, id);
    }
  } finally {
    vscode.window.showInformationMessage = originalInformation;
    vscode.window.showWarningMessage = originalWarning;
  }
  const applySnapshot = api.getRemediationApplySnapshot();
  assert.equal(applySnapshot.preview?.id, preview.id);
  assert.equal(applySnapshot.activeOperation?.stage, "preview-ready");
  assert.equal(applySnapshot.activeOperation?.previewId, preview.id);
  assert.equal(applySnapshot.history.length, 0);
  assert.equal(applySnapshot.lastResult, undefined);
  assert.equal(approvalPrompts.length, 0, "preview-only plans must never reach approval");
  assert.equal(messages.length, 3);
  assert.ok(
    messages.every((message) =>
      /Create and explicitly approve a remediation preview before applying a fix\./u.test(message),
    ),
    "preview-only, replayed, and traversal-shaped apply attempts must fail closed",
  );
  assertFixtureUnchanged(fixtureRoot, originalFixture);
  assert.equal(
    interceptor.requests.length,
    requestsBeforeRemediation,
    "preview generation and preview-only apply refusal must not start a validation rescan",
  );
  await vscode.commands.executeCommand(COMMANDS.cancelRemediation);
  assert.equal(api.getRemediationApplySnapshot().preview, undefined);
  return originalFixture;
}

async function runSmoke() {
  const mode = requiredEnvironment("PHASE4_OSV_MODE");
  assert.ok(mode === "mock" || mode === "real");
  const scenario = requiredEnvironment("PHASE5A_SCENARIO");
  assert.ok(
    [
      "partial",
      "complete",
      "remediation-preview",
    ].includes(scenario),
  );
  const temporaryRoot = path.resolve(requiredEnvironment("PHASE4_TEMP_ROOT"));
  const fixtureRoot = path.resolve(requiredEnvironment("PHASE4_FIXTURE_ROOT"));
  const userDataDirectory = path.resolve(requiredEnvironment("PHASE4_USER_DATA_DIR"));
  const extensionsDirectory = path.resolve(requiredEnvironment("PHASE4_EXTENSIONS_DIR"));
  const extensionRoot = path.resolve(requiredEnvironment("PHASE4_EXTENSION_ROOT"));
  const workspaceFile = path.resolve(requiredEnvironment("PHASE4_WORKSPACE_FILE"));
  assert.equal(requiredEnvironment("PHASE4_EXTENSION_ID"), EXTENSION_ID);
  for (const candidate of [
    fixtureRoot,
    userDataDirectory,
    extensionsDirectory,
    workspaceFile,
  ]) {
    assert.ok(isWithin(candidate, temporaryRoot));
  }
  assert.ok(fs.existsSync(path.join(temporaryRoot, "phase4-smoke.marker")));
  assert.match(vscode.version, /^1\.132\./u);
  assert.equal(vscode.workspace.isTrusted, true);
  const fixtureBefore = fixtureFileSnapshot(fixtureRoot);
  let expectedFixtureAfter = fixtureBefore;
  const workspaceFileBefore = fileByteSnapshot(workspaceFile);
  assert.ok(fixtureBefore.length > 0, "disposable fixture must contain files");

  const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
  assert.equal(workspaceFolders.length, scenario === "partial" ? 8 : 1);
  for (const folder of workspaceFolders) {
    assert.equal(folder.uri.scheme, "file");
    assert.ok(
      isWithin(path.resolve(folder.uri.fsPath), fixtureRoot),
      `workspace ${folder.name} escaped the disposable fixture root`,
    );
  }

  const interceptor = new OsvFetchInterceptor(mode);
  const executionGuard = new ProjectExecutionGuard(extensionRoot);
  interceptor.install();
  executionGuard.install();
  try {
    const extension = vscode.extensions.getExtension(EXTENSION_ID);
    assert.ok(extension, `exact extension ${EXTENSION_ID} must be installed for development`);
    assert.equal(extension.id, EXTENSION_ID);
    assert.equal(path.resolve(extension.extensionPath), extensionRoot);
    assert.equal(extension.packageJSON.version, "0.7.0");
    const api = await extension.activate();
    for (const method of [
      "getDashboardHtml",
      "getDetailsHtml",
      "getRemediationAnalysis",
      "getRemediationApplySnapshot",
      "getRemediationCenterHtml",
      "getSnapshot",
      "getStatusModel",
      "getTreeRootLabels",
    ]) {
      assert.equal(typeof api?.[method], "function", `test API ${method} is required`);
    }

    const registered = new Set(await vscode.commands.getCommands(true));
    for (const command of Object.values(COMMANDS)) {
      assert.ok(registered.has(command), `${command} must be registered`);
    }

    const initialSnapshot = await executeScanCommand(
      api,
      scenario === "partial" ? COMMANDS.scan : COMMANDS.refreshDatabase,
    );
    const initialResult =
      scenario === "partial"
        ? assertCoverageAndIdentity(initialSnapshot)
        : assertCompleteCoverageAndIdentity(
            initialSnapshot,
            scenario.startsWith("remediation-") ? 3 : 2,
            scenario.startsWith("remediation-") ? 3 : 1,
          );
    const requestCountAfterInitialScan = interceptor.requests.length;
    const initialExpectedIdentities =
      scenario === "partial"
        ? EXPECTED_IDENTITIES
        : new Set([
            JSON.stringify(["npm", "fixture-npm", "1.2.3"]),
            ...(scenario.startsWith("remediation-")
              ? [JSON.stringify(["npm", "fixture-donor", "1.0.0"])]
              : []),
            ...(scenario.startsWith("remediation-")
              ? [JSON.stringify(["npm", "fixture-npm", "1.2.4"])]
              : []),
          ]);
    const expectedIdentities = new Set(initialExpectedIdentities);
    assertExactIdentitySet(
      interceptor.uniqueIdentityKeys(),
      initialExpectedIdentities,
    );
    reportCoverage(initialResult, mode);
    const remediationAnalysis = assertRemediationAnalysis(
      api,
      initialSnapshot,
      interceptor,
      mode,
      scenario,
    );
    if (scenario === "partial") {
      await assertNoCompleteRemediation(api, interceptor);
    } else {
      await assertShowRemediation(api, interceptor);
    }
    if (mode === "mock") {
      assert.equal(interceptor.requests.length, initialExpectedIdentities.size);
      assert.equal(initialResult.vulnerabilities.length, 1);
      await assertMockFinding(api, fixtureRoot, interceptor);
    }

    if (mode === "mock" && scenario.startsWith("remediation-")) {
      expectedFixtureAfter = await assertPhase5BRemediation(
        api,
        fixtureRoot,
        interceptor,
        scenario,
      );
    }

    await vscode.commands.executeCommand(COMMANDS.showVulnerabilities);
    if (scenario === "partial") {
      assertTree(
        api,
        extension.extensionPath,
        initialSnapshot,
        remediationAnalysis,
        mode,
      );
      assertIncompleteStatus(api, mode === "mock");
      await assertDashboard(api);
    } else if (!scenario.startsWith("remediation-")) {
      const status = api.getStatusModel();
      assert.equal(status.coverageComplete, true);
      if (mode === "mock") {
        assert.match(status.text, /1 remediable/u);
        assert.match(status.tooltip, /no files have been changed/iu);
      }
      const html = api.getDashboardHtml();
      assertStrictCsp(html, "complete remediation dashboard");
      assert.match(html, /Remediation Coverage/u);
    }
    if (!scenario.startsWith("remediation-")) {
      assert.equal(
        interceptor.requests.length,
        requestCountAfterInitialScan,
        "remediation analysis, command, tree, status, dashboard, details, and Problems must not add provider requests",
      );
    }

    if (mode === "mock" && scenario === "partial") {
      // Re-scan with all deterministic provider results empty. The unresolved
      // Python requirement must still prevent a clean status and success card.
      interceptor.setFixtureVulnerability(false);
      const safePartial = await executeScanCommand(api, COMMANDS.refreshDatabase);
      const safeResult = assertCoverageAndIdentity(safePartial);
      assert.equal(safeResult.vulnerabilities.length, 0);
      assertIncompleteStatus(api);
      await assertDashboard(api);
    }

    if (!scenario.startsWith("remediation-")) {
      const requestCountBeforeCacheRefresh = interceptor.requests.length;
      const cachedRefresh = await executeScanCommand(api, COMMANDS.refreshScan);
      if (scenario === "partial") {
        assertCoverageAndIdentity(cachedRefresh);
      } else {
        assertCompleteCoverageAndIdentity(cachedRefresh);
      }
      assert.equal(
        interceptor.requests.length,
        requestCountBeforeCacheRefresh,
        "a refresh must reuse fresh cache entries rather than query OSV again",
      );
      const cachedProvider = cachedRefresh.latestAttempt[0].providerResults[0];
      assert.equal(cachedProvider.cacheHits, initialExpectedIdentities.size);
    }

    if (mode === "mock" && scenario === "partial") {
      // A second scan supersedes and aborts an intentionally hung provider
      // attempt. This exercises the real command cancellation path without a
      // test-only mutation API in production.
      interceptor.setBehavior("hang");
      const superseded = Promise.resolve(
        vscode.commands.executeCommand(COMMANDS.refreshDatabase),
      );
      superseded.catch(() => {
        // The original promise is still awaited below; this prevents a fast
        // command failure from becoming an unhandled rejection while polling.
      });
      await waitFor(() => interceptor.activeHangs > 0, "hung OSV requests");
      interceptor.setBehavior("success");
      const replacement = await executeScanCommand(api, COMMANDS.scan);
      assertCoverageAndIdentity(replacement);
      await withTimeout(superseded, "superseded scan cancellation");
      assert.ok(interceptor.abortedHangs > 0);
      assert.equal(api.getSnapshot().scanning, false);

      // Provider failures are not false-clean and do not destroy the previous
      // usable partial result shown in the dashboard.
      interceptor.setBehavior("failure");
      const failed = await executeScanCommand(api, COMMANDS.refreshDatabase);
      assert.equal(failed.latestAttemptCoverage, "unavailable");
      assert.equal(failed.latestAttempt[0].providerResults[0].status, "unavailable");
      assert.ok(
        failed.latestAttempt[0].errors.some((error) => error.code === "PROVIDER_ERROR"),
      );
      assertIncompleteStatus(api);
      const failureHtml = await assertDashboard(api);
      assert.match(failureHtml, /Vulnerability database unavailable\./u);
      interceptor.setBehavior("success");
    }

    assertExactIdentitySet(interceptor.uniqueIdentityKeys(), expectedIdentities);
    process.stdout.write(
      `Phase 5B extension-host smoke PASS (${mode}, ${scenario}); observed identities: ${[
        ...interceptor.uniqueIdentityKeys(),
      ].join(", ")}\n`,
    );
  } finally {
    executionGuard.restore();
    interceptor.restore();
    await closeNotifications();
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    assert.deepEqual(
      fixtureFileSnapshot(fixtureRoot),
      expectedFixtureAfter,
      "the disposable fixture must match the scenario's exact expected final bytes",
    );
    assert.deepEqual(
      fileByteSnapshot(workspaceFile),
      workspaceFileBefore,
      "the opened workspace descriptor must remain byte-for-byte unchanged",
    );
    assert.deepEqual(
      executionGuard.attempts,
      [],
      "Phase 5B must not execute processes, package managers, tasks, terminals, or project scripts",
    );
  }
}

exports.run = runSmoke;
