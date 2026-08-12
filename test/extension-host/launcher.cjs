"use strict";

/* eslint-disable @typescript-eslint/no-require-imports -- VS Code's extension-test entrypoint is CommonJS. */

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

function requiredEnvironment(name) {
  const value = process.env[name];
  assert.ok(value, `${name} must be set by scripts/phase4-smoke.ps1`);
  return value;
}

function resolvedDirectory(name) {
  return path.resolve(requiredEnvironment(name));
}

function assertWithin(candidate, parent, label) {
  const relative = path.relative(parent, candidate);
  assert.ok(
    relative.length === 0 ||
      (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative)),
    `${label} must remain under the disposable Phase 5B root`,
  );
}

function resolveVsCodeCli(executablePath) {
  const executableDirectory = path.dirname(executablePath);
  const direct = path.join(
    executableDirectory,
    "resources",
    "app",
    "out",
    "cli.js",
  );
  if (fs.existsSync(direct)) {
    return direct;
  }
  const matches = fs
    .readdirSync(executableDirectory, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^[a-f0-9]{10,64}$/u.test(entry.name))
    .map((entry) =>
      path.join(
        executableDirectory,
        entry.name,
        "resources",
        "app",
        "out",
        "cli.js",
      ),
    )
    .filter((candidate) => fs.existsSync(candidate))
    .sort(
      (left, right) =>
        fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs ||
        left.localeCompare(right),
    );
  assert.ok(matches.length >= 1, "at least one VS Code CLI entrypoint is required");
  return matches[0];
}

async function main() {
  const extensionMode = requiredEnvironment("PHASE4_EXTENSION_MODE");
  assert.ok(extensionMode === "development" || extensionMode === "installed");
  const extensionDevelopmentPath = resolvedDirectory("PHASE4_EXTENSION_ROOT");
  const packagedHarnessPath = path.join(
    extensionDevelopmentPath,
    "test",
    "extension-host",
    "packaged-harness",
  );
  const extensionTestsPath = path.join(
    extensionDevelopmentPath,
    "test",
    "extension-host",
    extensionMode === "installed" ? "packaged" : "suite",
    "index.cjs",
  );
  const temporaryRoot = resolvedDirectory("PHASE4_TEMP_ROOT");
  const workspaceFile = path.resolve(requiredEnvironment("PHASE4_WORKSPACE_FILE"));
  const fixtureRoot = resolvedDirectory("PHASE4_FIXTURE_ROOT");
  const userDataDirectory = resolvedDirectory("PHASE4_USER_DATA_DIR");
  const extensionsDirectory = resolvedDirectory("PHASE4_EXTENSIONS_DIR");
  const cachePath = resolvedDirectory("PHASE4_VSCODE_CACHE");
  const testElectronModule = path.resolve(
    requiredEnvironment("PHASE4_TEST_ELECTRON_MODULE"),
  );

  for (const [candidate, label] of [
    [workspaceFile, "workspace file"],
    [fixtureRoot, "fixture root"],
    [userDataDirectory, "user-data directory"],
    [extensionsDirectory, "extensions directory"],
    [cachePath, "VS Code download cache"],
    [testElectronModule, "@vscode/test-electron module"],
  ]) {
    assertWithin(candidate, temporaryRoot, label);
  }

  // This dependency is deliberately installed into a throw-away npm prefix by
  // the PowerShell driver; the extension's package.json remains unchanged.
  const { downloadAndUnzipVSCode, runTests } = require(testElectronModule);
  assert.equal(typeof runTests, "function");

  const extensionTestsEnv = {
    PHASE4_EXTENSION_ID: requiredEnvironment("PHASE4_EXTENSION_ID"),
    PHASE4_EXTENSION_MODE: extensionMode,
    PHASE4_EXTENSION_ROOT: extensionDevelopmentPath,
    PHASE4_EXTENSIONS_DIR: extensionsDirectory,
    PHASE4_FIXTURE_ROOT: fixtureRoot,
    PHASE4_OSV_MODE: requiredEnvironment("PHASE4_OSV_MODE"),
    PHASE4_TEMP_ROOT: temporaryRoot,
    PHASE4_USER_DATA_DIR: userDataDirectory,
    PHASE4_WORKSPACE_FILE: workspaceFile,
    PHASE5A_SCENARIO: requiredEnvironment("PHASE5A_SCENARIO"),
  };
  const options = {
    extensionDevelopmentPath:
      extensionMode === "installed" ? packagedHarnessPath : extensionDevelopmentPath,
    extensionTestsPath,
    extensionTestsEnv,
    launchArgs: [
      workspaceFile,
      ...(extensionMode === "development" ? ["--disable-extensions"] : []),
      "--disable-workspace-trust",
      "--disable-telemetry",
      "--disable-updates",
      "--skip-release-notes",
      "--skip-welcome",
      `--user-data-dir=${userDataDirectory}`,
      `--extensions-dir=${extensionsDirectory}`,
    ],
  };

  const installedExecutable = process.env.PHASE4_VSCODE_EXECUTABLE;
  let vscodeExecutablePath;
  if (installedExecutable) {
    vscodeExecutablePath = path.resolve(installedExecutable);
  } else {
    const version = requiredEnvironment("PHASE4_VSCODE_VERSION");
    // @vscode/test-electron 3.x keeps the downloaded archive and extraction in
    // this path, allowing the driver's validated cleanup to remove all state.
    vscodeExecutablePath = await downloadAndUnzipVSCode({ version, cachePath });
  }
  options.vscodeExecutablePath = vscodeExecutablePath;

  if (extensionMode === "installed") {
    const vsixPath = path.resolve(requiredEnvironment("PHASE4_VSIX_PATH"));
    assertWithin(vsixPath, extensionDevelopmentPath, "VSIX path");
    const cliPath = resolveVsCodeCli(vscodeExecutablePath);
    const install = childProcess.spawnSync(
      vscodeExecutablePath,
      [
        cliPath,
        `--user-data-dir=${userDataDirectory}`,
        `--extensions-dir=${extensionsDirectory}`,
        "--install-extension",
        vsixPath,
        "--force",
      ],
      {
        encoding: "utf8",
        env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
      },
    );
    process.stdout.write(install.stdout ?? "");
    process.stderr.write(install.stderr ?? "");
    assert.equal(
      install.status,
      0,
      `isolated VSIX installation failed: ${install.error?.message ?? "unknown error"}`,
    );
  }

  // Some integrated terminals inherit this variable from their extension host.
  // If it reaches a nested Code.exe, Electron runs the first workspace argument
  // as a Node.js script instead of starting VS Code.
  const inheritedElectronRunAsNode = process.env.ELECTRON_RUN_AS_NODE;
  delete process.env.ELECTRON_RUN_AS_NODE;
  try {
    await runTests(options);
  } finally {
    if (inheritedElectronRunAsNode !== undefined) {
      process.env.ELECTRON_RUN_AS_NODE = inheritedElectronRunAsNode;
    }
  }
}

main().catch((error) => {
  process.stderr.write(
    `Phase 5B extension-host launcher failed: ${error instanceof Error ? error.stack : String(error)}\n`,
  );
  process.exitCode = 1;
});
