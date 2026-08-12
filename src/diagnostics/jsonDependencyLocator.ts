const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

type DependencySection = string;
const MAXIMUM_TEXT_LENGTH = 2 * 1024 * 1024;
const MAXIMUM_NESTING_DEPTH = 128;
const MAXIMUM_TOKENS = 250_000;
const MAXIMUM_KEY_SOURCE_LENGTH = 4_096;
const MAXIMUM_MANIFEST_NAME_LENGTH = 512;
const MAXIMUM_REQUESTED_NAMES = 2_000;
const JSON_NUMBER =
  /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/u;

interface JsonStringToken {
  readonly contentStart: number;
  readonly contentEnd: number;
  readonly value?: string;
  readonly rawContent?: string;
}

interface DependencySectionResult {
  readonly valid: boolean;
  readonly offsets: ReadonlyMap<string, number>;
}

/**
 * A deliberately small, bounded JSON/JSON-with-comments reader. It never
 * constructs the manifest object; it only identifies direct object keys while
 * safely skipping every other value. This keeps diagnostic placement separate
 * from dependency parsing and prevents provider/workspace strings from
 * masquerading as dependency declarations.
 */
class DependencyKeyLocator {
  private index = 0;
  private tokenCount = 0;

  public constructor(
    private readonly text: string,
    private readonly manifestNames: ReadonlySet<string>,
    private readonly dependencySections: readonly string[],
    private readonly dependencySectionSet: ReadonlySet<string>,
  ) {}

  public locate(): ReadonlyMap<string, number> {
    const sectionOffsets = new Map<
      DependencySection,
      ReadonlyMap<string, number>
    >();
    if (!this.skipTrivia() || !this.consumeCharacter("{")) {
      return new Map();
    }
    if (!this.skipTrivia()) {
      return new Map();
    }
    if (this.consumeCharacter("}")) {
      return this.finish(new Map());
    }

    while (this.index < this.text.length) {
      const key = this.readString(true);
      if (key === undefined || !this.skipTrivia() || !this.consumeCharacter(":")) {
        return new Map();
      }
      if (!this.skipTrivia()) {
        return new Map();
      }

      if (
        key.value !== undefined &&
        this.dependencySectionSet.has(key.value)
      ) {
        const section = key.value as DependencySection;
        const result = this.readDependencySection();
        if (!result.valid) {
          return new Map();
        }
        // JSON's last duplicate object key wins. Replacing the entire map
        // prevents an ignored earlier duplicate section from supplying an
        // anchor that is absent from the effective section value.
        sectionOffsets.set(section, result.offsets);
      } else if (!this.skipValue(1)) {
        return new Map();
      }

      if (!this.skipTrivia()) {
        return new Map();
      }
      if (this.consumeCharacter("}")) {
        const selected = new Map<string, number>();
        for (const manifestName of this.manifestNames) {
          for (const section of this.dependencySections) {
            const offset = sectionOffsets.get(section)?.get(manifestName);
            if (offset !== undefined) {
              selected.set(manifestName, offset);
              break;
            }
          }
        }
        return this.finish(selected);
      }
      if (!this.consumeCharacter(",") || !this.skipTrivia()) {
        return new Map();
      }
    }
    return new Map();
  }

  private finish(
    offsets: ReadonlyMap<string, number>,
  ): ReadonlyMap<string, number> {
    return this.skipTrivia() && this.index === this.text.length
      ? offsets
      : new Map();
  }

  private readDependencySection(): DependencySectionResult {
    if (this.text[this.index] !== "{") {
      return {
        valid: this.skipValue(1),
        offsets: new Map(),
      };
    }
    if (!this.consumeCharacter("{") || !this.skipTrivia()) {
      return { valid: false, offsets: new Map() };
    }
    if (this.consumeCharacter("}")) {
      return { valid: true, offsets: new Map() };
    }

    const selectedOffsets = new Map<string, number>();
    while (this.index < this.text.length) {
      const key = this.readString(true);
      if (key === undefined || !this.skipTrivia() || !this.consumeCharacter(":")) {
        return { valid: false, offsets: new Map() };
      }
      if (!this.skipTrivia() || !this.skipValue(2)) {
        return { valid: false, offsets: new Map() };
      }

      if (
        key.value !== undefined &&
        this.manifestNames.has(key.value)
      ) {
        // DiagnosticManager currently receives only an offset and highlights
        // manifestName.length characters. Escaped spellings are therefore
        // intentionally left unanchored rather than returning an inaccurate
        // range.
        if (key.rawContent === key.value) {
          selectedOffsets.set(key.value, key.contentStart);
        } else {
          selectedOffsets.delete(key.value);
        }
      }

      if (!this.skipTrivia()) {
        return { valid: false, offsets: new Map() };
      }
      if (this.consumeCharacter("}")) {
        return { valid: true, offsets: selectedOffsets };
      }
      if (!this.consumeCharacter(",") || !this.skipTrivia()) {
        return { valid: false, offsets: new Map() };
      }
    }
    return { valid: false, offsets: new Map() };
  }

  private skipValue(depth: number): boolean {
    if (depth > MAXIMUM_NESTING_DEPTH || !this.consumeToken()) {
      return false;
    }
    const character = this.text[this.index];
    if (character === '"') {
      return this.readString(false, false) !== undefined;
    }
    if (character === "{") {
      return this.skipObject(depth);
    }
    if (character === "[") {
      return this.skipArray(depth);
    }

    const start = this.index;
    while (this.index < this.text.length) {
      const current = this.text[this.index];
      if (
        current === "," ||
        current === "]" ||
        current === "}" ||
        current === "/" ||
        current === " " ||
        current === "\t" ||
        current === "\r" ||
        current === "\n"
      ) {
        break;
      }
      this.index += 1;
    }
    const primitive = this.text.slice(start, this.index);
    return (
      primitive === "true" ||
      primitive === "false" ||
      primitive === "null" ||
      JSON_NUMBER.test(primitive)
    );
  }

  private skipObject(depth: number): boolean {
    if (!this.consumeCharacter("{") || !this.skipTrivia()) {
      return false;
    }
    if (this.consumeCharacter("}")) {
      return true;
    }
    while (this.index < this.text.length) {
      if (
        this.readString(false) === undefined ||
        !this.skipTrivia() ||
        !this.consumeCharacter(":") ||
        !this.skipTrivia() ||
        !this.skipValue(depth + 1) ||
        !this.skipTrivia()
      ) {
        return false;
      }
      if (this.consumeCharacter("}")) {
        return true;
      }
      if (!this.consumeCharacter(",") || !this.skipTrivia()) {
        return false;
      }
    }
    return false;
  }

  private skipArray(depth: number): boolean {
    if (!this.consumeCharacter("[") || !this.skipTrivia()) {
      return false;
    }
    if (this.consumeCharacter("]")) {
      return true;
    }
    while (this.index < this.text.length) {
      if (!this.skipValue(depth + 1) || !this.skipTrivia()) {
        return false;
      }
      if (this.consumeCharacter("]")) {
        return true;
      }
      if (!this.consumeCharacter(",") || !this.skipTrivia()) {
        return false;
      }
    }
    return false;
  }

  private readString(
    decode: boolean,
    countToken = true,
  ): JsonStringToken | undefined {
    if (
      this.text[this.index] !== '"' ||
      (countToken && !this.consumeToken())
    ) {
      return undefined;
    }
    const sourceStart = this.index;
    const contentStart = sourceStart + 1;
    this.index += 1;

    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (character === undefined) {
        return undefined;
      }
      if (character === '"') {
        const contentEnd = this.index;
        this.index += 1;
        if (!decode || contentEnd - contentStart > MAXIMUM_KEY_SOURCE_LENGTH) {
          return { contentStart, contentEnd };
        }
        const source = this.text.slice(sourceStart, this.index);
        try {
          const parsed: unknown = JSON.parse(source);
          if (typeof parsed !== "string") {
            return undefined;
          }
          return {
            contentStart,
            contentEnd,
            value: parsed,
            rawContent: this.text.slice(contentStart, contentEnd),
          };
        } catch {
          return undefined;
        }
      }
      if (character === "\\") {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === "u") {
          const hexadecimal = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9A-Fa-f]{4}$/u.test(hexadecimal)) {
            return undefined;
          }
          this.index += 5;
          continue;
        }
        if (
          escaped === undefined ||
          !['"', "\\", "/", "b", "f", "n", "r", "t"].includes(escaped)
        ) {
          return undefined;
        }
        this.index += 1;
        continue;
      }
      if (character.charCodeAt(0) <= 0x1f) {
        return undefined;
      }
      this.index += 1;
    }
    return undefined;
  }

  private skipTrivia(): boolean {
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (
        character === " " ||
        character === "\t" ||
        character === "\r" ||
        character === "\n"
      ) {
        this.index += 1;
        continue;
      }
      if (character !== "/") {
        return true;
      }
      const next = this.text[this.index + 1];
      if (next === "/") {
        this.index += 2;
        while (
          this.index < this.text.length &&
          this.text[this.index] !== "\r" &&
          this.text[this.index] !== "\n"
        ) {
          this.index += 1;
        }
        continue;
      }
      if (next === "*") {
        const end = this.text.indexOf("*/", this.index + 2);
        if (end === -1) {
          return false;
        }
        this.index = end + 2;
        continue;
      }
      return true;
    }
    return true;
  }

  private consumeCharacter(expected: string): boolean {
    if (this.text[this.index] !== expected) {
      return false;
    }
    this.index += 1;
    return true;
  }

  private consumeToken(): boolean {
    this.tokenCount += 1;
    return this.tokenCount <= MAXIMUM_TOKENS;
  }
}

function isEligibleManifestName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAXIMUM_MANIFEST_NAME_LENGTH &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

/**
 * Locates up to 2,000 requested dependency keys in one bounded pass. Keys that
 * cannot be anchored exactly (including escaped source spellings) are omitted.
 */
export function findDependencyOffsets(
  text: string,
  manifestNames: readonly string[],
): ReadonlyMap<string, number> {
  if (text.length === 0 || text.length > MAXIMUM_TEXT_LENGTH) {
    return new Map();
  }
  const selectedNames = new Set<string>();
  const requestedCount = Math.min(
    manifestNames.length,
    MAXIMUM_REQUESTED_NAMES,
  );
  for (let index = 0; index < requestedCount; index += 1) {
    const manifestName = manifestNames[index];
    if (isEligibleManifestName(manifestName)) {
      selectedNames.add(manifestName);
    }
  }
  return findDependencyOffsetsInSections(
    text,
    [...selectedNames],
    DEPENDENCY_SECTIONS,
  );
}

export function findDependencyOffsetsInSections(
  text: string,
  manifestNames: readonly string[],
  sections: readonly string[],
): ReadonlyMap<string, number> {
  if (
    text.length === 0 ||
    text.length > MAXIMUM_TEXT_LENGTH ||
    sections.length === 0 ||
    sections.length > 16
  ) {
    return new Map();
  }
  const selectedNames = new Set<string>();
  for (
    let index = 0;
    index < Math.min(manifestNames.length, MAXIMUM_REQUESTED_NAMES);
    index += 1
  ) {
    const manifestName = manifestNames[index];
    if (isEligibleManifestName(manifestName)) {
      selectedNames.add(manifestName);
    }
  }
  const selectedSections = sections.filter(
    (section, index) =>
      isEligibleManifestName(section) && sections.indexOf(section) === index,
  );
  return selectedNames.size === 0 || selectedSections.length === 0
    ? new Map()
    : new DependencyKeyLocator(
        text,
        selectedNames,
        selectedSections,
        new Set(selectedSections),
      ).locate();
}

export function findDependencyOffset(
  text: string,
  manifestName: string,
): number | undefined {
  return findDependencyOffsets(text, [manifestName]).get(manifestName);
}
