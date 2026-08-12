import type {
  DetectedPackageManager,
  PackageManagerHint,
  PackageManagerId,
} from "../models/discovery";
import { PACKAGE_MANAGER_IDS } from "../models/discovery";

export const DEPENDENCY_FILE_GLOB =
  "**/{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock,pnpm-lock.yaml,pnpm-workspace.yaml,bun.lock,bun.lockb,bunfig.toml,.npmrc,.yarnrc,.yarnrc.yml,requirements.txt,requirements-*.txt,requirements_*.txt,pyproject.toml,setup.py,setup.cfg,poetry.lock,Pipfile,Pipfile.lock,pom.xml,.mvn/maven.config,.mvn/jvm.config,.mvn/extensions.xml,build.gradle,build.gradle.kts,settings.gradle,settings.gradle.kts,gradle.lockfile,packages.config,packages.lock.json,packages.*.lock.json,NuGet.Config,NuGet.config,nuget.config,Directory.Packages.props,directory.packages.props,Directory.Build.props,directory.build.props,Directory.Build.targets,directory.build.targets,*.csproj,*.fsproj,*.vbproj,Cargo.toml,Cargo.lock,go.mod,go.sum,composer.json,composer.lock}";

export const GENERATED_DIRECTORY_GLOB =
  "**/{.git,.hg,.svn,.yarn,.pnpm-store,node_modules,bower_components,vendor,target,dist,build,out,coverage,.next,.nuxt,.turbo,.nx,.cache,.gradle,.venv,venv,__pycache__}/**";

const DISPLAY_NAMES: Readonly<Record<PackageManagerId, string>> = {
  npm: "npm",
  yarn: "Yarn",
  pnpm: "pnpm",
  bun: "Bun",
  pip: "pip",
  poetry: "Poetry",
  pipenv: "Pipenv",
  maven: "Maven",
  gradle: "Gradle",
  nuget: "NuGet",
  cargo: "Cargo",
  go: "Go modules",
  composer: "Composer",
};

const JAVASCRIPT_MANAGERS = new Set<PackageManagerId>([
  "npm",
  "yarn",
  "pnpm",
  "bun",
]);

const PYTHON_MANAGERS = new Set<PackageManagerId>([
  "pip",
  "poetry",
  "pipenv",
]);

const PACKAGE_MANAGER_HINT_PATTERN =
  /^(npm|yarn|pnpm|bun)@[0-9A-Za-z*][0-9A-Za-z._+*~^<>=|-]{0,239}$/u;

interface MutableDetection {
  readonly evidence: Set<string>;
  inferred: boolean;
}

function normalizeRelativePath(filePath: string): string {
  return filePath
    .replaceAll("\\", "/")
    .replace(/^(?:\.\/)+/u, "")
    .replace(/\/{2,}/gu, "/");
}

function baseName(filePath: string): string {
  const segments = normalizeRelativePath(filePath).split("/");
  return (segments.at(-1) ?? "").toLowerCase();
}

function directoryName(filePath: string): string {
  const normalized = normalizeRelativePath(filePath);
  const separatorIndex = normalized.lastIndexOf("/");
  return separatorIndex === -1 ? "" : normalized.slice(0, separatorIndex);
}

function isSameOrAncestorDirectory(
  possibleAncestor: string,
  directory: string,
): boolean {
  return (
    possibleAncestor === "" ||
    possibleAncestor === directory ||
    directory.startsWith(`${possibleAncestor}/`)
  );
}

function managerFromPackageManagerHint(value: string): PackageManagerId | undefined {
  const trimmed = value.trim();
  if (trimmed.length > 256) {
    return undefined;
  }
  const match = PACKAGE_MANAGER_HINT_PATTERN.exec(trimmed);
  return match?.[1]?.toLowerCase() as PackageManagerId | undefined;
}

function managerFromFileName(
  fileName: string,
  filePath: string,
): PackageManagerId | undefined {
  if (fileName === "package-lock.json" || fileName === "npm-shrinkwrap.json") {
    return "npm";
  }
  if (fileName === "yarn.lock") {
    return "yarn";
  }
  if (fileName === "pnpm-lock.yaml" || fileName === "pnpm-workspace.yaml") {
    return "pnpm";
  }
  if (fileName === "bun.lock" || fileName === "bun.lockb") {
    return "bun";
  }
  if (
    (fileName.startsWith("requirements") && fileName.endsWith(".txt")) ||
    fileName === "setup.py" ||
    fileName === "setup.cfg"
  ) {
    return "pip";
  }
  if (fileName === "poetry.lock") {
    return "poetry";
  }
  if (fileName === "pipfile" || fileName === "pipfile.lock") {
    return "pipenv";
  }
  if (
    fileName === "pom.xml" ||
    ((fileName === "maven.config" ||
      fileName === "jvm.config" ||
      fileName === "extensions.xml") &&
      /(?:^|\/)\.mvn\/(?:maven\.config|jvm\.config|extensions\.xml)$/u.test(
        filePath,
      ))
  ) {
    return "maven";
  }
  if (
    fileName === "build.gradle" ||
    fileName === "build.gradle.kts" ||
    fileName === "settings.gradle" ||
    fileName === "settings.gradle.kts" ||
    fileName === "gradle.lockfile"
  ) {
    return "gradle";
  }
  if (
    fileName === "packages.config" ||
    fileName === "packages.lock.json" ||
    /^packages\..+\.lock\.json$/u.test(fileName) ||
    fileName === "nuget.config" ||
    fileName === "directory.packages.props" ||
    fileName === "directory.build.props" ||
    fileName === "directory.build.targets" ||
    fileName.endsWith(".csproj") ||
    fileName.endsWith(".fsproj") ||
    fileName.endsWith(".vbproj")
  ) {
    return "nuget";
  }
  if (fileName === "cargo.toml" || fileName === "cargo.lock") {
    return "cargo";
  }
  if (fileName === "go.mod" || fileName === "go.sum") {
    return "go";
  }
  if (fileName === "composer.json" || fileName === "composer.lock") {
    return "composer";
  }
  return undefined;
}

function addDetection(
  detections: Map<PackageManagerId, MutableDetection>,
  id: PackageManagerId,
  evidence: string,
  inferred: boolean,
): void {
  const existing = detections.get(id);
  if (existing !== undefined) {
    existing.evidence.add(evidence);
    existing.inferred &&= inferred;
    return;
  }

  detections.set(id, {
    evidence: new Set([evidence]),
    inferred,
  });
}

function hasAncestorSignal(
  filePath: string,
  signalDirectories: readonly string[],
): boolean {
  const directory = directoryName(filePath);
  return signalDirectories.some((signalDirectory) =>
    isSameOrAncestorDirectory(signalDirectory, directory),
  );
}

export function detectPackageManagers(
  dependencyFiles: readonly string[],
  packageManagerHints: readonly PackageManagerHint[] = [],
): readonly DetectedPackageManager[] {
  const detections = new Map<PackageManagerId, MutableDetection>();
  const packageJsonFiles: string[] = [];
  const pyprojectFiles: string[] = [];
  const javascriptSignalDirectories: string[] = [];
  const pythonSignalDirectories: string[] = [];
  const unsupportedHintDirectories: string[] = [];

  for (const rawFilePath of new Set(dependencyFiles)) {
    const filePath = normalizeRelativePath(rawFilePath);
    const fileName = baseName(filePath);
    if (fileName === "package.json") {
      packageJsonFiles.push(filePath);
      continue;
    }
    if (fileName === "pyproject.toml") {
      pyprojectFiles.push(filePath);
      continue;
    }

    const manager = managerFromFileName(fileName, filePath);
    if (manager !== undefined) {
      addDetection(detections, manager, filePath, false);
      if (JAVASCRIPT_MANAGERS.has(manager)) {
        javascriptSignalDirectories.push(directoryName(filePath));
      }
      if (PYTHON_MANAGERS.has(manager)) {
        pythonSignalDirectories.push(directoryName(filePath));
      }
    }
  }

  for (const hint of packageManagerHints) {
    const manager = managerFromPackageManagerHint(hint.value);
    if (manager === undefined) {
      unsupportedHintDirectories.push(directoryName(hint.source));
      continue;
    }

    addDetection(
      detections,
      manager,
      `${normalizeRelativePath(hint.source)}#packageManager`,
      false,
    );
    javascriptSignalDirectories.push(directoryName(hint.source));
  }

  for (const packageJsonFile of packageJsonFiles) {
    if (
      !hasAncestorSignal(packageJsonFile, javascriptSignalDirectories) &&
      !hasAncestorSignal(packageJsonFile, unsupportedHintDirectories)
    ) {
      addDetection(detections, "npm", packageJsonFile, true);
    }
  }

  for (const pyprojectFile of pyprojectFiles) {
    if (!hasAncestorSignal(pyprojectFile, pythonSignalDirectories)) {
      addDetection(detections, "pip", pyprojectFile, true);
    }
  }

  return PACKAGE_MANAGER_IDS.flatMap((id) => {
    const detection = detections.get(id);
    if (detection === undefined) {
      return [];
    }
    return [
      {
        id,
        displayName: DISPLAY_NAMES[id],
        evidence: [...detection.evidence].sort((left, right) =>
          left.localeCompare(right),
        ),
        inferred: detection.inferred,
      },
    ];
  });
}

export function findUnsupportedPackageManagerHints(
  hints: readonly PackageManagerHint[],
): readonly PackageManagerHint[] {
  return hints.filter(
    (hint) => managerFromPackageManagerHint(hint.value) === undefined,
  );
}

export function findAmbiguousJavaScriptManagers(
  managers: readonly DetectedPackageManager[],
): readonly DetectedPackageManager[] {
  return managers.filter(
    (manager) => JAVASCRIPT_MANAGERS.has(manager.id) && !manager.inferred,
  );
}
