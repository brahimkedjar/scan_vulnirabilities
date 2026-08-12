/**
 * Static Poetry marker detection used before an unlocked pyproject is parsed.
 * The adapter has already bounded the file to 4 MiB; the additional line and
 * line-length ceilings keep this recognition pass predictably linear.
 */
export const MAX_POETRY_MANIFEST_DETECTION_CHARACTERS = 4 * 1024 * 1024;
export const MAX_POETRY_MANIFEST_DETECTION_LINES = 100_000;
const MAX_POETRY_MANIFEST_DETECTION_LINE_LENGTH = 16 * 1024;

const SECTION = /^\s*\[\s*([^\]]{1,256})\s*\]\s*(?:#.*)?$/u;
const POETRY_BUILD_BACKEND =
  /^\s*build-backend\s*=\s*(["'])poetry\.core\.masonry\.api\1\s*(?:#.*)?$/u;

export type PoetryManifestDetection =
  | "poetry"
  | "not-poetry"
  | "indeterminate";

export function detectPoetryManifest(text: string): PoetryManifestDetection {
  if (text.length > MAX_POETRY_MANIFEST_DETECTION_CHARACTERS) {
    return "indeterminate";
  }

  let currentSection = "";
  let projectSectionPresent = false;
  let poetryBuildBackendPresent = false;
  let inspectionIncomplete = false;
  let offset = 0;
  let lines = 0;

  while (offset < text.length && lines < MAX_POETRY_MANIFEST_DETECTION_LINES) {
    const newline = text.indexOf("\n", offset);
    const end = newline === -1 ? text.length : newline;
    const lineEnd = end > offset && text.charCodeAt(end - 1) === 13 ? end - 1 : end;
    const lineLength = lineEnd - offset;
    lines += 1;

    if (lineLength <= MAX_POETRY_MANIFEST_DETECTION_LINE_LENGTH) {
      const line = text.slice(offset, lineEnd);
      const section = SECTION.exec(line)?.[1]?.trim().toLowerCase();
      if (section !== undefined) {
        currentSection = section;
        if (
          section === "tool.poetry" ||
          section.startsWith("tool.poetry.") ||
          section === "dependency-groups"
        ) {
          return "poetry";
        }
        projectSectionPresent ||= section === "project";
      } else if (
        currentSection === "build-system" &&
        POETRY_BUILD_BACKEND.test(line)
      ) {
        poetryBuildBackendPresent = true;
      }
    } else {
      inspectionIncomplete = true;
    }

    if (projectSectionPresent && poetryBuildBackendPresent) {
      return "poetry";
    }
    if (newline === -1) {
      offset = text.length;
      break;
    }
    offset = newline + 1;
  }
  if (offset < text.length) {
    inspectionIncomplete = true;
  }
  return inspectionIncomplete ? "indeterminate" : "not-poetry";
}

/** Compatibility predicate for callers that do not need the gap reason. */
export function isPoetryManifest(text: string): boolean {
  return detectPoetryManifest(text) === "poetry";
}
