import { strict as assert } from "node:assert";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

interface CommandContribution {
  readonly command?: unknown;
  readonly title?: unknown;
  readonly category?: unknown;
}

interface ExtensionManifest {
  readonly activationEvents?: unknown;
  readonly main?: unknown;
  readonly contributes?: {
    readonly commands?: readonly CommandContribution[];
    readonly viewsContainers?: {
      readonly activitybar?: readonly { readonly id?: unknown }[];
    };
    readonly views?: Record<
      string,
      readonly { readonly id?: unknown; readonly type?: unknown }[]
    >;
    readonly configuration?: {
      readonly properties?: Record<
        string,
        { readonly default?: unknown; readonly type?: unknown }
      >;
    };
  };
}

async function readManifest(): Promise<ExtensionManifest> {
  const projectRoot = resolve(__dirname, "..", "..");
  const contents = await readFile(resolve(projectRoot, "package.json"), "utf8");
  const parsed: unknown = JSON.parse(contents);

  assert.equal(typeof parsed, "object");
  assert.notEqual(parsed, null);
  return parsed as ExtensionManifest;
}

void test("manifest contributes the Phase 5B commands, view, and settings", async () => {
  const manifest = await readManifest();

  assert.equal(manifest.main, "./dist/extension.js");
  assert.equal(Array.isArray(manifest.activationEvents), true);
  assert.equal(
    (manifest.activationEvents as readonly unknown[]).includes(
      "onStartupFinished",
    ),
    true,
  );
  for (const command of ["previewFix", "applyFix", "cancelRemediation"]) {
    assert.equal(
      (manifest.activationEvents as readonly unknown[]).includes(
        `onCommand:dependencyAuditor.${command}`,
      ),
      true,
    );
  }
  assert.equal(
    (manifest.activationEvents as readonly unknown[]).includes(
      "onCommand:dependencyAuditor.scanWorkspace",
    ),
    true,
  );
  assert.equal(
    (manifest.activationEvents as readonly unknown[]).includes(
      "onCommand:dependencyAuditor.showRemediation",
    ),
    true,
  );

  const commands = manifest.contributes?.commands;
  assert.equal(Array.isArray(commands), true);
  assert.deepEqual(
    commands?.map((command) => command.command),
    [
      "dependencyAuditor.scanWorkspace",
      "dependencyAuditor.showDashboard",
      "dependencyAuditor.refreshScan",
      "dependencyAuditor.showVulnerabilities",
      "dependencyAuditor.refreshVulnerabilityDatabase",
      "dependencyAuditor.showRemediation",
      "dependencyAuditor.previewFix",
      "dependencyAuditor.applyFix",
      "dependencyAuditor.cancelRemediation",
    ],
  );
  assert.equal(
    manifest.contributes?.viewsContainers?.activitybar?.[0]?.id,
    "dependencyAuditor",
  );
  assert.equal(
    manifest.contributes?.views?.dependencyAuditor?.[0]?.id,
    "dependencyAuditor.securityView",
  );
  assert.deepEqual(manifest.contributes?.views?.dependencyAuditor?.[1], {
    id: "dependencyAuditor.remediationView",
    name: "Remediation",
    type: "webview",
    contextualTitle: "Dependency Remediation",
  });
  const properties = manifest.contributes?.configuration?.properties;
  assert.deepEqual(properties?.["dependencyAuditor.enabled"], {
    type: "boolean",
    default: true,
    markdownDescription:
      "Enable dependency vulnerability scanning and related UI.",
  });
  assert.equal(
    properties?.["dependencyAuditor.scanOnStartup"]?.default,
    false,
  );
  assert.equal(properties?.["dependencyAuditor.scanOnChange"]?.default, false);
  assert.equal(properties?.["dependencyAuditor.minimumSeverity"]?.default, "UNKNOWN");
  assert.equal(
    properties?.["dependencyAuditor.includeDevDependencies"]?.default,
    true,
  );
  assert.equal(
    properties?.["dependencyAuditor.includeTransitiveDependencies"]?.default,
    true,
  );
  assert.deepEqual(
    properties?.["dependencyAuditor.cacheDuration"],
    {
      type: "number",
      default: 24,
      minimum: 0.25,
      maximum: 720,
      markdownDescription:
        "How many hours a successful OSV response remains fresh. Empty successful responses are cached; provider errors are not.",
    },
  );
});
