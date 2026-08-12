"use strict";

/* eslint-disable @typescript-eslint/no-require-imports -- VS Code loads this test runner through CommonJS. */

const assert = require("node:assert/strict");
const path = require("node:path");
const vscode = require("vscode");

const EXTENSION_ID = "c9aeb496-ae78-660b-a56e-b4102ed5df53.dependency-vulnerability-auditor";
const COMMANDS = Object.freeze([
  "dependencyAuditor.scanWorkspace",
  "dependencyAuditor.refreshScan",
  "dependencyAuditor.refreshVulnerabilityDatabase",
  "dependencyAuditor.showDashboard",
  "dependencyAuditor.showVulnerabilities",
  "dependencyAuditor.showVulnerabilityDetails",
  "dependencyAuditor.showRemediation",
  "dependencyAuditor.previewFix",
  "dependencyAuditor.applyFix",
  "dependencyAuditor.cancelRemediation",
]);

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

async function dismissNotifications() {
  for (const command of [
    "notifications.clearAll",
    "workbench.action.closeMessages",
  ]) {
    try {
      await vscode.commands.executeCommand(command);
    } catch {
      // Command availability differs across VS Code builds; either one closes
      // the informational message that this test intentionally exercises.
    }
  }
}

async function executeWithNotificationDismissal(command, timeoutMs = 10_000) {
  let settled = false;
  let rejected = false;
  let commandError;
  const pending = Promise.resolve(vscode.commands.executeCommand(command)).then(
    () => {
      settled = true;
    },
    (error) => {
      settled = true;
      rejected = true;
      commandError = error;
    },
  );
  const deadline = Date.now() + timeoutMs;
  while (!settled && Date.now() < deadline) {
    await wait(50);
    await dismissNotifications();
  }
  await dismissNotifications();
  if (!settled) {
    throw new Error(
      `${command} did not settle after its informational notification was dismissed`,
    );
  }
  await pending;
  if (rejected) {
    throw commandError;
  }
}

exports.run = async function runPackagedSmoke() {
  assert.equal(requiredEnvironment("PHASE4_EXTENSION_MODE"), "installed");
  const extensionsDirectory = path.resolve(
    requiredEnvironment("PHASE4_EXTENSIONS_DIR"),
  );
  const extension = vscode.extensions.getExtension(EXTENSION_ID);
  assert.ok(extension, `installed extension ${EXTENSION_ID} was not discovered`);
  assert.ok(isWithin(path.resolve(extension.extensionPath), extensionsDirectory));
  assert.equal(extension.packageJSON.version, "0.7.0");

  await extension.activate();
  assert.equal(extension.isActive, true);
  const registered = new Set(await vscode.commands.getCommands(true));
  for (const command of COMMANDS) {
    assert.ok(registered.has(command), `${command} must be registered`);
  }

  await vscode.commands.executeCommand("dependencyAuditor.showDashboard");
  await vscode.commands.executeCommand("dependencyAuditor.showVulnerabilities");
  await vscode.commands.executeCommand(
    "dependencyAuditor.showVulnerabilityDetails",
    Object.freeze({}),
  );
  // With no scan state the command intentionally awaits an informational
  // notification. Drain it until the command settles so a slow Extension Host
  // cannot race a one-shot clear and hang this unattended smoke.
  await executeWithNotificationDismissal("dependencyAuditor.showRemediation");
  await executeWithNotificationDismissal("dependencyAuditor.previewFix");
  await executeWithNotificationDismissal("dependencyAuditor.applyFix");
  await vscode.commands.executeCommand("dependencyAuditor.cancelRemediation");
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  process.stdout.write(
    `Phase 5B packaged VSIX activation PASS (${extension.id}@${extension.packageJSON.version})\n`,
  );
};
