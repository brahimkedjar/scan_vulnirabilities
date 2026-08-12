import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseGradleProject } from "../package-managers/gradle/gradleParser";
import { parseMavenPom } from "../package-managers/maven/mavenParser";
import { parsePipenvProject } from "../package-managers/pipenv/pipenvParser";
import { parsePoetryProject } from "../package-managers/poetry/poetryParser";
import { parseRequirements } from "../package-managers/python/requirementsParser";

const fixtures = join(process.cwd(), "src", "test", "fixtures");

function fixture(...parts: readonly string[]): string {
  return readFileSync(join(fixtures, ...parts), "utf8");
}

void test("Python requirements separates exact, ranged, and non-registry declarations", () => {
  const result = parseRequirements({
    text: fixture("python", "requirements.txt"),
    manifestPath: "/workspace/requirements.txt",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    environment: "production",
  });

  assert.equal(result.dependencies.length, 4);
  const requests = result.dependencies.find(
    (dependency) => dependency.name === "requests",
  );
  assert.equal(requests?.installedVersion, "2.31.0");
  assert.equal(requests?.resolutionStatus, "resolved");
  assert.deepEqual(requests?.metadata?.extras, ["socks"]);
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "django")
      ?.resolutionStatus,
    "unresolved",
  );
  assert.equal(
    result.dependencies.find(
      (dependency) => dependency.name === "custom-package",
    )?.resolutionStatus,
    "unsupported",
  );
});

void test("Poetry lock is authoritative and builds a direct/transitive path", async () => {
  const result = await parsePoetryProject({
    pyprojectText: fixture("poetry", "pyproject.toml"),
    lockfileText: fixture("poetry", "poetry.lock"),
    manifestPath: "/workspace/pyproject.toml",
    lockfilePath: "/workspace/poetry.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 3);
  const requests = result.dependencies.find(
    (dependency) => dependency.name === "requests",
  );
  const urllib3 = result.dependencies.find(
    (dependency) => dependency.name === "urllib3",
  );
  assert.equal(requests?.dependencyType, "direct");
  assert.equal(requests?.installedVersion, "2.31.0");
  assert.equal(urllib3?.dependencyType, "transitive");
  assert.equal(urllib3?.parent, "requests@2.31.0");
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "pytest")
      ?.environment,
    "development",
  );
});

void test("Pipenv distinguishes default, develop, direct, and transitive entries", async () => {
  const result = await parsePipenvProject({
    pipfileText: fixture("pipenv", "Pipfile"),
    lockfileText: fixture("pipenv", "Pipfile.lock"),
    manifestPath: "/workspace/Pipfile",
    lockfilePath: "/workspace/Pipfile.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 3);
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "requests")
      ?.dependencyType,
    "direct",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "urllib3")
      ?.dependencyType,
    "transitive",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "pytest")
      ?.environment,
    "development",
  );
});

void test("Maven preserves groupId:artifactId and resolves local properties and management", () => {
  const result = parseMavenPom({
    text: fixture("maven", "pom.xml"),
    manifestPath: "/workspace/pom.xml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 4);
  assert.equal(
    result.dependencies.find(
      (dependency) =>
        dependency.name === "org.apache.commons:commons-text",
    )?.installedVersion,
    "1.9",
  );
  const junit = result.dependencies.find(
    (dependency) =>
      dependency.name === "org.junit.jupiter:junit-jupiter",
  );
  assert.equal(junit?.installedVersion, "5.10.2");
  assert.equal(junit?.environment, "development");
  assert.equal(junit?.manifestName, "junit-jupiter");
  assert.equal(
    result.dependencies.find(
      (dependency) => dependency.name === "example:dynamic",
    )?.resolutionStatus,
    "unresolved",
  );
  assert.equal(
    result.dependencies.find(
      (dependency) => dependency.name === "example:system-library",
    )?.resolutionStatus,
    "unsupported",
  );
});

void test("Gradle lock reconciles direct selections and leaves graphless entries unresolved", () => {
  const result = parseGradleProject({
    scriptText: fixture("gradle", "build.gradle.kts"),
    lockfileText: fixture("gradle", "gradle.lockfile"),
    manifestPath: "/workspace/build.gradle.kts",
    lockfilePath: "/workspace/gradle.lockfile",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 5);
  const springCore = result.dependencies.find(
    (dependency) => dependency.name === "org.springframework:spring-core",
  );
  assert.equal(springCore?.installedVersion, "5.3.39");
  assert.equal(springCore?.dependencyType, "direct");
  const springJcl = result.dependencies.find(
    (dependency) => dependency.name === "org.springframework:spring-jcl",
  );
  assert.equal(springJcl?.dependencyType, "transitive");
  assert.equal(springJcl?.installedVersion, "");
  assert.equal(springJcl?.resolutionStatus, "unresolved");
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.message.includes("graphless transitive coordinates"),
    ),
  );
  assert.equal(
    result.dependencies.some(
      (dependency) => dependency.name === "commented:dependency",
    ),
    false,
  );
});

void test("Gradle declarations remain unresolved without selected lock state", () => {
  const result = parseGradleProject({
    scriptText: 'dependencies { implementation("com.acme:widget:1.0.0") }',
    manifestPath: "/workspace/build.gradle.kts",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 1);
  assert.equal(result.dependencies[0]?.requestedVersion, "1.0.0");
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "com.acme:widget",
    ),
  );
});

void test("Maven rejects a document type without expanding it", () => {
  const result = parseMavenPom({
    text: '<!DOCTYPE project [<!ENTITY x "boom">]><project>&x;</project>',
    manifestPath: "/workspace/pom.xml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(result.dependencies.length, 0);
  assert.equal(result.errors[0]?.code, "INVALID_MANIFEST");
});
