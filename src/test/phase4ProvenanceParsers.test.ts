import { strict as assert } from "node:assert";
import { test } from "node:test";

import { parseCargoDependencies } from "../package-managers/cargo/CargoDependencyParser";
import { parseComposerDependencies } from "../package-managers/composer/ComposerDependencyParser";
import { parseGradleProject } from "../package-managers/gradle/gradleParser";
import { parseMavenPom } from "../package-managers/maven/mavenParser";
import { parseNugetDependencies } from "../package-managers/nuget/NugetDependencyParser";
import { parsePipenvProject } from "../package-managers/pipenv/pipenvParser";
import { parsePoetryProject } from "../package-managers/poetry/poetryParser";

const project = {
  manifestPath: "/workspace/manifest",
  projectPath: "/workspace",
  workspacePath: "/workspace",
} as const;

function poetryLock(source = ""): string {
  return `[[package]]
name = "private-package"
version = "1.2.3"
${source}
[metadata]
lock-version = "2.1"
`;
}

void test("Poetry manifest source constraints dominate stale lock provenance", async () => {
  const result = await parsePoetryProject({
    pyprojectText: `[tool.poetry]
name = "app"
version = "1.0.0"
[tool.poetry.dependencies]
python = "^3.11"
private-package = { version = "1.2.3", source = "private" }
[[tool.poetry.source]]
name = "private"
url = "https://private.example/simple"
priority = "explicit"
`,
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });

  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE"),
  );
});

void test("Poetry custom primary sources make implicit lock provenance unsupported", async () => {
  const result = await parsePoetryProject({
    pyprojectText: `[tool.poetry.dependencies]
private-package = "1.2.3"
[[tool.poetry.source]]
name = "private"
url = "https://private.example/simple"
priority = "primary"
`,
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });

  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Poetry source-list truncation fails closed before a hidden private primary", async () => {
  const explicitSources = Array.from(
    { length: 256 },
    (_, index) => `[[tool.poetry.source]]
name = "explicit-${index.toString()}"
url = "https://private.example/${index.toString()}/simple"
priority = "explicit"
`,
  ).join("\n");
  const result = await parsePoetryProject({
    pyprojectText: `[tool.poetry.dependencies]
private-package = "1.2.3"
${explicitSources}
[[tool.poetry.source]]
name = "hidden-primary"
url = "https://private.example/simple"
priority = "primary"
`,
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });

  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE"),
  );
});

void test("Poetry accepts only explicit canonical PyPI provenance", async () => {
  const canonical = await parsePoetryProject({
    pyprojectText: `[tool.poetry.dependencies]
private-package = { version = "1.2.3", source = "pypi" }
[[tool.poetry.source]]
name = "pypi"
priority = "primary"
`,
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });
  const spoofedLock = await parsePoetryProject({
    pyprojectText: `[tool.poetry.dependencies]
private-package = "1.2.3"
`,
    lockfileText: poetryLock(
      `[package.source]\ntype = "legacy"\nurl = "https://pypi.org.evil.example/simple"\nreference = "private"`,
    ),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });

  assert.equal(canonical.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(spoofedLock.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Poetry reports manifest declarations absent from a stale lock", async () => {
  const result = await parsePoetryProject({
    pyprojectText: `[tool.poetry.dependencies]
private-package = "1.2.3"
brand-new = "2.0.0"
`,
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });
  const missing = result.dependencies.find(
    (dependency) => dependency.name === "brand-new",
  );
  assert.equal(missing?.resolutionStatus, "unresolved");
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "brand-new",
    ),
  );
});

void test("Poetry rejects lock selections outside manifest constraints", async () => {
  for (const requested of ["2.0.0", "^2.0.0"]) {
    const result = await parsePoetryProject({
      pyprojectText: `[tool.poetry.dependencies]\nprivate-package = "${requested}"\n`,
      lockfileText: poetryLock(),
      ...project,
      lockfilePath: "/workspace/poetry.lock",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  }
});

void test("Poetry treats PEP 508 direct URLs as unsupported provenance", async () => {
  const result = await parsePoetryProject({
    pyprojectText:
      '[project]\ndependencies = ["private-package @ https://private.example/private-package.whl"]\n',
    lockfileText: poetryLock(),
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Poetry validates transitive constraints and never publishes orphan lock packages", async () => {
  const result = await parsePoetryProject({
    pyprojectText: '[tool.poetry.dependencies]\na = "^1"\n',
    lockfileText: `[[package]]
name = "a"
version = "1.0.0"
[package.dependencies]
b = ">=2"
[[package]]
name = "b"
version = "1.0.0"
[[package]]
name = "orphan"
version = "9.9.9"
[metadata]
lock-version = "2.1"
`,
    ...project,
    lockfilePath: "/workspace/poetry.lock",
  });
  assert.equal(
    result.dependencies.find((entry) => entry.name === "a")?.resolutionStatus,
    "resolved",
  );
  for (const name of ["b", "orphan"]) {
    const dependency = result.dependencies.find((entry) => entry.name === name);
    assert.equal(dependency?.installedVersion, "");
    assert.equal(dependency?.resolutionStatus, "unresolved");
  }
});

function pipenvLock(
  sources: unknown,
  entry: Readonly<Record<string, unknown>> = { version: "==1.2.3" },
): string {
  return JSON.stringify({
    _meta: { "pipfile-spec": 6, ...(sources === undefined ? {} : { sources }) },
    default: { "private-package": entry },
    develop: {},
  });
}

void test("Pipenv manifest private index dominates stale public lock metadata", async () => {
  const result = await parsePipenvProject({
    pipfileText: `[[source]]
name = "private"
url = "https://private.example/simple"
verify_ssl = true
[packages]
private-package = { version = "==1.2.3", index = "private" }
`,
    lockfileText: pipenvLock([
      { name: "pypi", url: "https://pypi.org/simple", verify_ssl: true },
    ]),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });

  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(
    result.dependencies[0]?.metadata?.sourceConfiguration,
    "mismatch",
  );
});

void test("Pipenv requires lock source provenance when Pipfile declares sources", async () => {
  const result = await parsePipenvProject({
    pipfileText: `[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true
[packages]
private-package = "==1.2.3"
`,
    lockfileText: pipenvLock(undefined),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });

  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Pipenv accepts matching canonical PyPI source metadata", async () => {
  const sources = [
    { name: "pypi", url: "https://pypi.org/simple", verify_ssl: true },
  ];
  const result = await parsePipenvProject({
    pipfileText: `[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true
[packages]
private-package = { version = "==1.2.3", index = "pypi" }
`,
    lockfileText: pipenvLock(sources, {
      version: "==1.2.3",
      index: "pypi",
    }),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });

  assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
  assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(result.errors.length, 0);
});

void test("Pipenv reports manifest declarations absent from a stale lock", async () => {
  const sources = [
    { name: "pypi", url: "https://pypi.org/simple", verify_ssl: true },
  ];
  const result = await parsePipenvProject({
    pipfileText: `[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true
[packages]
private-package = "==1.2.3"
brand-new = "==2.0.0"
`,
    lockfileText: pipenvLock(sources),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });
  const missing = result.dependencies.find(
    (dependency) => dependency.name === "brand-new",
  );
  assert.equal(missing?.resolutionStatus, "unresolved");
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "brand-new",
    ),
  );
});

void test("Pipenv rejects exact and range selections outside Pipfile constraints", async () => {
  for (const requested of ["==2.0.0", ">=2.0.0,<3.0.0"]) {
    const result = await parsePipenvProject({
      pipfileText: `[packages]\nprivate-package = "${requested}"\n`,
      lockfileText: pipenvLock(undefined),
      ...project,
      lockfilePath: "/workspace/Pipfile.lock",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  }
});

void test("Pipenv treats direct URL strings as unsupported provenance", async () => {
  const result = await parsePipenvProject({
    pipfileText:
      '[packages]\nprivate-package = "https://private.example/private-package.whl"\n',
    lockfileText: pipenvLock(undefined),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Pipenv does not infer public provenance for unindexed entries with a private secondary source", async () => {
  const sources = [
    { name: "pypi", url: "https://pypi.org/simple", verify_ssl: true },
    {
      name: "private",
      url: "https://private.example/simple",
      verify_ssl: true,
    },
  ];
  const result = await parsePipenvProject({
    pipfileText: `[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true
[[source]]
name = "private"
url = "https://private.example/simple"
verify_ssl = true
[packages]
public-root = { version = "==1.0.0", index = "pypi" }
`,
    lockfileText: JSON.stringify({
      _meta: { "pipfile-spec": 6, sources },
      default: {
        "public-root": { version: "==1.0.0", index: "pypi" },
        "company-secret-transitive": { version: "==2.3.4" },
      },
      develop: {},
    }),
    ...project,
    lockfilePath: "/workspace/Pipfile.lock",
  });
  assert.equal(
    result.dependencies.find((entry) => entry.name === "public-root")
      ?.resolutionStatus,
    "resolved",
  );
  assert.equal(
    result.dependencies.find(
      (entry) => entry.name === "company-secret-transitive",
    )?.resolutionStatus,
    "unsupported",
  );
});

function pom(repositoryUrl?: string): string {
  const repositories =
    repositoryUrl === undefined
      ? ""
      : `<repositories><repository><id>selected</id><url>${repositoryUrl}</url></repository></repositories>`;
  return `<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId><artifactId>app</artifactId><version>1</version>${repositories}<dependencies><dependency><groupId>com.private</groupId><artifactId>secret</artifactId><version>1.2.3</version></dependency></dependencies></project>`;
}

void test("Maven custom repository provenance makes reached dependencies unsupported", () => {
  const result = parseMavenPom({
    text: pom("https://private.example/repository"),
    ...project,
  });

  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE"),
  );
});

void test("Maven permits absent and exact canonical Central repository configuration", () => {
  for (const text of [pom(), pom("https://repo.maven.apache.org/maven2/")]) {
    const result = parseMavenPom({ text, ...project });
    assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
    assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  }
  const spoofed = parseMavenPom({
    text: pom("https://repo.maven.apache.org.evil.example/maven2"),
    ...project,
  });
  assert.equal(spoofed.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Maven applies repository provenance inherited from an ancestor POM", () => {
  const child = `<project><modelVersion>4.0.0</modelVersion><parent><groupId>app</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId><dependencies><dependency><groupId>com.private</groupId><artifactId>secret</artifactId><version>1.2.3</version></dependency></dependencies></project>`;
  const parentPrefix = `<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId><artifactId>parent</artifactId><version>1</version>`;
  const custom = parseMavenPom({
    text: child,
    repositoryConfigurationTexts: [
      `${parentPrefix}<repositories><repository><url>https://private.example/repository</url></repository></repositories></project>`,
    ],
    ...project,
  });
  const canonical = parseMavenPom({
    text: child,
    repositoryConfigurationTexts: [`${parentPrefix}</project>`],
    ...project,
  });
  assert.equal(custom.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(canonical.dependencies[0]?.resolutionStatus, "resolved");
});

void test("Maven fails closed when workspace Maven configuration changes provenance", () => {
  for (const configuration of [
    "--settings .mvn/settings.xml",
    "-s=.mvn/settings.xml",
    "--global-settings ../settings.xml",
    "-gs ../settings.xml",
    "-s.mvn/settings.xml",
    "-gs.mvn/settings.xml",
    "-ssettings.xml",
    "-gssettings.xml",
    "\"--settings\" \".mvn/settings.xml\"",
    "-Dmaven.repo.local=.m2/private-cache",
    "-o",
    "--offline",
    "-f alternate-pom.xml",
    "-falternate-pom.xml",
    "--file=alternate-pom.xml",
  ]) {
    const result = parseMavenPom({
      text: pom(),
      mavenConfigurationTexts: [configuration],
      ...project,
    });
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.ok(
      result.errors.some(
        (error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ),
    );
  }

  const safeOption = parseMavenPom({
    text: pom(),
    mavenConfigurationTexts: ["-DskipTests -fae", "-Xmx2g -XX:+UseG1GC"],
    ...project,
  });
  assert.equal(safeOption.dependencies[0]?.resolutionStatus, "resolved");
});

void test("Maven jvm.config rejects a private local repository but permits JVM tuning", () => {
  const hostile = parseMavenPom({
    text: pom(),
    mavenConfigurationTexts: [
      "-Xmx2g -Dmaven.repo.local=.mvn/private-repository",
    ],
    ...project,
  });
  const safe = parseMavenPom({
    text: pom(),
    mavenConfigurationTexts: ["-Xmx2g -XX:+UseG1GC"],
    ...project,
  });
  assert.equal(hostile.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(hostile.dependencies[0]?.installedVersion, "");
  assert.equal(safe.dependencies[0]?.resolutionStatus, "resolved");
});

void test("Maven build extensions and .mvn/extensions.xml fail source provenance closed", () => {
  const buildExtension = parseMavenPom({
    text: pom().replace(
      "<dependencies>",
      "<build><extensions><extension><groupId>com.example</groupId><artifactId>resolver-extension</artifactId><version>1.0.0</version></extension></extensions></build><dependencies>",
    ),
    ...project,
  });
  const workspaceExtension = parseMavenPom({
    text: pom(),
    mavenExtensionTexts: [
      "<extensions><extension><groupId>com.example</groupId><artifactId>resolver-extension</artifactId><version>1.0.0</version></extension></extensions>",
    ],
    ...project,
  });
  const safe = parseMavenPom({ text: pom(), ...project });

  for (const result of [buildExtension, workspaceExtension]) {
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
    assert.ok(
      result.errors.some(
        (error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ),
    );
  }
  assert.equal(safe.dependencies[0]?.resolutionStatus, "resolved");
});

function gradle(scriptPrefix: string): ReturnType<typeof parseGradleProject> {
  return parseGradleProject({
    scriptText: `${scriptPrefix}\ndependencies { implementation("com.private:secret:1.2.3") }`,
    lockfileText: "com.private:secret:1.2.3=runtimeClasspath\n",
    ...project,
    lockfilePath: "/workspace/gradle.lockfile",
  });
}

void test("Gradle custom repository provenance makes locked modules unsupported", () => {
  const result = gradle(
    'repositories { maven { url = uri("https://private.example/repository") } }',
  );

  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE"),
  );
});

void test("Gradle rejects custom repository handler access outside repository blocks", () => {
  for (const prefix of [
    'repositories.maven { url = uri("https://private.example/repository") }',
    'project.repositories.maven { url = uri("https://private.example/repository") }',
  ]) {
    const result = gradle(prefix);
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
    assert.ok(
      result.errors.some(
        (error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ),
    );
  }

  assert.equal(
    gradle("repositories.mavenCentral()").dependencies[0]?.resolutionStatus,
    "resolved",
  );
});

void test("Gradle fails closed when applied scripts can inject repository logic", () => {
  for (const appliedScript of [
    'apply from: "repositories.gradle"',
    'apply(from = "repositories.gradle.kts")',
    'apply { from("repositories.gradle.kts") }',
    'apply { from "repositories.gradle" }',
    'apply(mapOf("from" to "repositories.gradle.kts"))',
    'apply([from: "repositories.gradle"])',
  ]) {
    assert.equal(gradle(appliedScript).dependencies[0]?.resolutionStatus, "unsupported");
    const inherited = parseGradleProject({
      scriptText:
        'dependencies { implementation("com.private:secret:1.2.3") }',
      repositoryConfigurationTexts: [appliedScript],
      lockfileText: "com.private:secret:1.2.3=runtimeClasspath\n",
      ...project,
      lockfilePath: "/workspace/gradle.lockfile",
    });
    assert.equal(inherited.dependencies[0]?.resolutionStatus, "unsupported");
  }
});

void test("Gradle fails closed when plugins can inject dependency repositories", () => {
  const pluginDeclaration =
    'plugins { id("com.company.private-repository-policy") version "1.0.0" }';
  const direct = gradle(pluginDeclaration);
  assert.equal(direct.dependencies[0]?.installedVersion, "");
  assert.equal(direct.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(
    direct.dependencies[0]?.metadata?.repositorySource,
    "custom-or-unresolved",
  );
  assert.ok(
    direct.errors.some(
      (error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
  );

  for (const repositoryConfigurationText of [
    pluginDeclaration,
    `pluginManagement { ${pluginDeclaration} }`,
  ]) {
    const inherited = parseGradleProject({
      scriptText:
        'dependencies { implementation("com.private:secret:1.2.3") }',
      repositoryConfigurationTexts: [repositoryConfigurationText],
      lockfileText: "com.private:secret:1.2.3=runtimeClasspath\n",
      ...project,
      lockfilePath: "/workspace/gradle.lockfile",
    });
    assert.equal(
      inherited.dependencies[0]?.resolutionStatus,
      "unsupported",
      repositoryConfigurationText,
    );
  }

  // Comments and an empty plugins block execute no plugin code and remain
  // distinguishable from a nonempty block under the conservative policy.
  assert.equal(
    gradle(
      'plugins { /* id("com.company.private-repository-policy") */ }',
    ).dependencies[0]?.resolutionStatus,
    "resolved",
  );
  assert.equal(
    gradle("plugins { java }").dependencies[0]?.resolutionStatus,
    "resolved",
  );
  assert.equal(
    gradle("plugins {}\n".repeat(257)).dependencies[0]?.resolutionStatus,
    "unsupported",
  );
});

void test("Gradle permits absent and canonical Maven Central declarations only", () => {
  for (const prefix of [
    "",
    "repositories { mavenCentral() }",
    'repositories { maven { url = uri("https://repo.maven.apache.org/maven2") } }',
  ]) {
    const result = gradle(prefix);
    assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
    assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  }
  const spoofed = gradle(
    'repositories { maven { url = "https://repo1.maven.org.evil.example/maven2" } }',
  );
  assert.equal(spoofed.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Gradle applies repository provenance from settings.gradle", () => {
  const result = parseGradleProject({
    scriptText:
      'dependencies { implementation("com.private:secret:1.2.3") }',
    repositoryConfigurationTexts: [
      'dependencyResolutionManagement { repositories { maven { url = uri("https://private.example/repository") } } }',
    ],
    lockfileText: "com.private:secret:1.2.3=runtimeClasspath\n",
    ...project,
    lockfilePath: "/workspace/gradle.lockfile",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.errors.some((error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE"),
  );
});

void test("Gradle applies custom repository provenance from ancestor build scripts", () => {
  const result = parseGradleProject({
    scriptText:
      'dependencies { implementation("com.private:secret:1.2.3") }',
    repositoryConfigurationTexts: [
      'allprojects { repositories { maven { url = "https://private.example/repository" } } }',
    ],
    lockfileText: "com.private:secret:1.2.3=runtimeClasspath\n",
    ...project,
    lockfilePath: "/workspace/gradle.lockfile",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Gradle reports version-catalog, project, and map dependency notation gaps", () => {
  for (const statement of [
    "implementation(libs.guava)",
    "implementation(project(':local'))",
    'implementation group: "com.google.guava", name: "guava", version: "33.0.0-jre"',
  ]) {
    const result = parseGradleProject({
      scriptText: `dependencies {\n${statement}\n}`,
      ...project,
    });
    assert.ok(
      result.errors.some((error) => error.code === "DEPENDENCY_UNRESOLVED"),
      statement,
    );
  }
});

void test("Gradle reports conditional and nested dependency declarations as coverage gaps", () => {
  for (const scriptText of [
    'dependencies { if (true) { implementation("org.private:secret:1.2.3") } }',
    `dependencies {
  if (true) {
    implementation("org.private:secret:1.2.3")
  }
}`,
  ]) {
    const result = parseGradleProject({ scriptText, ...project });
    assert.equal(result.dependencies.length, 0);
    assert.ok(
      result.errors.some((error) => error.code === "DEPENDENCY_UNRESOLVED"),
    );
  }
});

void test("Gradle rejects lock selections when the dependencies block is unclosed", () => {
  const result = parseGradleProject({
    scriptText:
      'dependencies {\n implementation("org.example:secret:2.+")',
    lockfileText: "org.example:secret:1.0=runtimeClasspath\n",
    ...project,
    lockfilePath: "/workspace/gradle.lockfile",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.ok(result.errors.some((error) => error.code === "INVALID_MANIFEST"));
});

void test("Gradle fails lock selection closed for unsupported dependency DSL calls", () => {
  for (const scriptText of [
    'dependencies.add("implementation", "org.example:secret:2.+")',
    'dependencies { kapt("org.example:secret:2.+") }',
    'dependencies { ksp("org.example:secret:2.+") }',
    'dependencies { customConfig("org.example:secret:2.+") }',
    'dependencies { classpath("org.example:secret:2.+") }',
    'dependencies { "implementation"("org.example:secret:2.+") }',
  ]) {
    const result = parseGradleProject({
      scriptText,
      lockfileText: "org.example:secret:1.0=runtimeClasspath\n",
      ...project,
      lockfilePath: "/workspace/gradle.lockfile",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "", scriptText);
    assert.equal(
      result.dependencies[0]?.resolutionStatus,
      "unresolved",
      scriptText,
    );
    assert.ok(
      result.errors.some((error) => error.code === "DEPENDENCY_UNRESOLVED"),
      scriptText,
    );
  }
});

void test("Gradle rejects stale exact and interval lock selections", () => {
  for (const requested of ["2.0.0", "[2.0,3.0)"]) {
    const result = parseGradleProject({
      scriptText: `dependencies { implementation("com.example:stale:${requested}") }`,
      lockfileText: "com.example:stale:1.0.0=runtimeClasspath\n",
      ...project,
      lockfilePath: "/workspace/gradle.lockfile",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  }
});

void test("Gradle rejects dynamic versions forged into selected lock state", () => {
  const result = parseGradleProject({
    scriptText: "plugins {}",
    lockfileText: "org.example:lib:1.+=runtimeClasspath\n",
    ...project,
    lockfilePath: "/workspace/gradle.lockfile",
  });
  assert.equal(
    result.dependencies.some(
      (dependency) => dependency.resolutionStatus === "resolved",
    ),
    false,
  );
  assert.ok(result.errors.some((error) => error.code === "INVALID_LOCKFILE"));
});

void test("Maven rejects dynamic versions as installed releases", () => {
  const result = parseMavenPom({
    text: pom().replace("1.2.3", "1.+"),
    ...project,
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
});

function nugetLock(): string {
  return JSON.stringify({
    version: 1,
    dependencies: {
      "net8.0": {
        "Private.Package": {
          type: "Direct",
          requested: "[1.2.3, )",
          resolved: "1.2.3",
          contentHash: "fixture",
        },
      },
    },
  });
}

void test("NuGet custom NuGet.config package sources make lock packages unsupported", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    nugetConfigXmls: [
      '<configuration><packageSources><clear/><add key="private" value="https://private.example/v3/index.json" /></packageSources></configuration>',
    ],
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.issues.some(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
  );
});

void test("NuGet permits absent and exact nuget.org package source configuration", () => {
  for (const nugetConfigXmls of [
    undefined,
    [
      '<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>',
    ],
  ] as const) {
    const result = parseNugetDependencies({
      projectXml:
        '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
      ...(nugetConfigXmls === undefined ? {} : { nugetConfigXmls }),
      lockfile: nugetLock(),
      manifestPath: "/workspace/App.csproj",
      lockfilePath: "/workspace/packages.lock.json",
      projectPath: "/workspace",
      workspacePath: "/workspace",
    });
    assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  }
});

void test("NuGet fails closed when an applicable source hierarchy exceeds its bound", () => {
  const canonical =
    '<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>';
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    nugetConfigXmls: Array.from({ length: 33 }, () => canonical),
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(result.issues.some((issue) => issue.code === "DEPENDENCY_LIMIT"));
});

void test("NuGet rejects a stale direct lock selection that violates the project constraint", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="[2.0.0]" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
});

void test("NuGet fails closed for project-level restore source overrides", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><PropertyGroup><RestoreSources>https://private.example/v3/index.json</RestoreSources></PropertyGroup><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("NuGet fails closed when project or props imports can inject restore sources", () => {
  const projectXml =
    '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>';
  const cases = [
    {
      projectXml: projectXml.replace(
        "<ItemGroup>",
        '<Import Project="repositories.props" /><ItemGroup>',
      ),
    },
    {
      projectXml,
      directoryPackagesPropsXmls: [
        '<Project><ImportGroup><Import Project="repositories.props" /></ImportGroup></Project>',
      ],
    },
    {
      projectXml,
      restoreConfigurationXmls: [
        '<Project><Import Project="repositories.props" /></Project>',
      ],
    },
  ] as const;
  for (const input of cases) {
    const result = parseNugetDependencies({
      ...input,
      lockfile: nugetLock(),
      manifestPath: "/workspace/App.csproj",
      lockfilePath: "/workspace/packages.lock.json",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
    assert.ok(
      result.issues.some(
        (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ),
    );
  }
});

void test("NuGet rejects custom MSBuild SDKs that can inject restore sources", () => {
  for (const projectXml of [
    '<Project Sdk="Private.Build.Sdk/1.0.0"><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    '<Project><Sdk Name="Private.Build.Sdk" Version="1.0.0"/><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
  ]) {
    const result = parseNugetDependencies({
      projectXml,
      lockfile: nugetLock(),
      manifestPath: "/workspace/App.csproj",
      lockfilePath: "/workspace/packages.lock.json",
    });
    assert.equal(result.dependencies[0]?.installedVersion, "");
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
    assert.ok(
      result.issues.some(
        (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ),
    );
  }

  const builtIn = parseNugetDependencies({
    projectXml:
      '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(builtIn.dependencies[0]?.resolutionStatus, "resolved");
});

void test("NuGet applies ancestor Directory.Build props and targets restore provenance", () => {
  const base = {
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/child/App.csproj",
    lockfilePath: "/workspace/child/packages.lock.json",
  } as const;
  const privateSource = parseNugetDependencies({
    ...base,
    restoreConfigurationXmls: [
      '<Project><PropertyGroup><RestoreSources>https://private.example/v3/index.json</RestoreSources></PropertyGroup></Project>',
    ],
  });
  const canonicalSource = parseNugetDependencies({
    ...base,
    restoreConfigurationXmls: [
      '<Project><PropertyGroup><RestoreSources>https://api.nuget.org/v3/index.json</RestoreSources></PropertyGroup></Project>',
    ],
  });
  const absentSource = parseNugetDependencies({
    ...base,
    restoreConfigurationXmls: ["<Project><PropertyGroup /></Project>"],
  });
  assert.equal(privateSource.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(canonicalSource.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(absentSource.dependencies[0]?.resolutionStatus, "resolved");
});

void test("NuGet fails closed for a private source inherited from Directory.Build.targets", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    restoreConfigurationXmls: [
      '<Project><PropertyGroup><RestoreSources>https://private.example/v3/index.json</RestoreSources></PropertyGroup></Project>',
    ],
    lockfile: nugetLock(),
    manifestPath: "/workspace/child/App.csproj",
    lockfilePath: "/workspace/child/packages.lock.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.ok(
    result.issues.some(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
  );
});

void test("NuGet rejects conditional and interpolated restore source provenance", () => {
  const base = {
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
  } as const;
  for (const xml of [
    '<Project><PropertyGroup Condition="\'$(Configuration)\' == \'Release\'"><RestoreSources>https://api.nuget.org/v3/index.json</RestoreSources></PropertyGroup></Project>',
    '<Project><PropertyGroup><RestoreSources>$(PrivateFeed)</RestoreSources></PropertyGroup></Project>',
  ]) {
    const result = parseNugetDependencies({
      ...base,
      restoreConfigurationXmls: [xml],
    });
    assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  }
});

void test("NuGet reconciles literal central versions and fails closed when none match", () => {
  const base = {
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Private.Package" /></ItemGroup></Project>',
    lockfile: nugetLock(),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  } as const;
  const matched = parseNugetDependencies({
    ...base,
    directoryPackagesPropsXmls: [
      '<Project><ItemGroup><PackageVersion Include="Private.Package" Version="1.2.3" /></ItemGroup></Project>',
    ],
  });
  const missing = parseNugetDependencies({
    ...base,
    directoryPackagesPropsXmls: [
      '<Project><ItemGroup><PackageVersion Include="Other.Package" Version="1.2.3" /></ItemGroup></Project>',
    ],
  });
  assert.equal(matched.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(missing.dependencies[0]?.resolutionStatus, "unresolved");
});

void test("NuGet validates transitive constraints and never publishes orphan lock packages", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="A" Version="[1.0.0]" /></ItemGroup></Project>',
    lockfile: JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          A: {
            type: "Direct",
            requested: "[1.0.0, )",
            resolved: "1.0.0",
            dependencies: { B: "[2.0.0, )" },
          },
          B: { type: "Transitive", resolved: "1.0.0" },
          Orphan: { type: "Transitive", resolved: "9.9.9" },
        },
      },
    }),
    manifestPath: "/workspace/App.csproj",
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(
    result.dependencies.find((entry) => entry.name === "A")?.resolutionStatus,
    "resolved",
  );
  for (const name of ["B", "Orphan"]) {
    const dependency = result.dependencies.find((entry) => entry.name === name);
    assert.equal(dependency?.installedVersion, "");
    assert.equal(dependency?.resolutionStatus, "unresolved");
  }
});

void test("Cargo rejects a lock node outside the manifest requirement", () => {
  const result = parseCargoDependencies({
    cargoToml:
      '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nfoo = "^2.0.0"\n',
    cargoLock:
      'version = 3\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]\n[[package]]\nname = "foo"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    manifestPath: "/workspace/Cargo.toml",
    lockfilePath: "/workspace/Cargo.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
});

void test("Cargo does not promote an orphan lock package to a direct dependency", () => {
  const result = parseCargoDependencies({
    cargoToml:
      '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nfoo = "1"\n',
    cargoLock:
      'version = 3\n[[package]]\nname = "app"\nversion = "0.1.0"\n[[package]]\nname = "foo"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    manifestPath: "/workspace/Cargo.toml",
    lockfilePath: "/workspace/Cargo.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
});

void test("Cargo exposes source-less patched nodes while traversing registry children", () => {
  const result = parseCargoDependencies({
    cargoToml:
      '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nfoo = "^1.0.0"\n',
    cargoLock: `version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["local 0.5.0"]
[[package]]
name = "local"
version = "0.5.0"
dependencies = ["child 1.1.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "child"
version = "1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
    manifestPath: "/workspace/Cargo.toml",
    lockfilePath: "/workspace/Cargo.lock",
  });
  const local = result.dependencies.find((entry) => entry.name === "local");
  const child = result.dependencies.find((entry) => entry.name === "child");
  assert.equal(local?.resolutionStatus, "unsupported");
  assert.equal(local?.installedVersion, "");
  assert.equal(child?.resolutionStatus, "resolved");
});

void test("Composer rejects lock selections outside root constraints", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"vendor/package":"^2.0"}}',
    composerLock: JSON.stringify({
      packages: [{ name: "vendor/package", version: "1.0.0" }],
      "packages-dev": [],
    }),
    manifestPath: "/workspace/composer.json",
    lockfilePath: "/workspace/composer.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
});

void test("Composer rejects Packagist lookalikes on non-default ports", () => {
  const result = parseComposerDependencies({
    composerJson: JSON.stringify({
      repositories: [
        { type: "composer", url: "https://repo.packagist.org:444/" },
      ],
      require: { "vendor/package": "1.0.0" },
    }),
    composerLock: JSON.stringify({
      packages: [{ name: "vendor/package", version: "1.0.0" }],
      "packages-dev": [],
    }),
    manifestPath: "/workspace/composer.json",
    lockfilePath: "/workspace/composer.lock",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});

void test("Composer validates transitive lock constraints", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"vendor/a":"^1"}}',
    composerLock: JSON.stringify({
      packages: [
        { name: "vendor/a", version: "1.0.0", require: { "vendor/b": "^2" } },
        { name: "vendor/b", version: "1.0.0" },
      ],
      "packages-dev": [],
    }),
    manifestPath: "/workspace/composer.json",
    lockfilePath: "/workspace/composer.lock",
  });
  const child = result.dependencies.find((entry) => entry.name === "vendor/b");
  assert.equal(child?.installedVersion, "");
  assert.equal(child?.resolutionStatus, "unresolved");
});

void test("Composer treats non-public lock artifact hosts as unsupported provenance", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"company/internal":"1.2.3"}}',
    composerLock: JSON.stringify({
      packages: [
        {
          name: "company/internal",
          version: "1.2.3",
          dist: {
            type: "zip",
            url: "https://packages.example.invalid/internal.zip",
          },
        },
      ],
      "packages-dev": [],
    }),
    manifestPath: "/workspace/composer.json",
    lockfilePath: "/workspace/composer.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
});
