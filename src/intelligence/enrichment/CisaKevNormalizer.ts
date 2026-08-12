import type {
  CisaKevCatalog,
  CisaKevEntry,
  CisaKevRansomwareUse,
} from "./CisaKevModels";

export const CISA_KEV_LIMITS = Object.freeze({
  maximumEntries: 10_000,
  maximumCwesPerEntry: 64,
  maximumStringLength: 8_192,
  maximumShortStringLength: 512,
});

const CVE_PATTERN = /^CVE-(?:19|20)\d{2}-\d{4,19}$/u;
const CWE_PATTERN = /^CWE-\d{1,10}$/u;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/u;
const CONTROL_OR_BIDI =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertSafeRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (UNSAFE_KEYS.has(key)) {
      throw new TypeError(`${path} contains an unsafe key`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new TypeError(`${path} contains an unsafe property`);
    }
  }
  return value;
}

function text(
  value: unknown,
  path: string,
  maximumLength: number = CISA_KEV_LIMITS.maximumStringLength,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    CONTROL_OR_BIDI.test(value)
  ) {
    throw new TypeError(`${path} is invalid`);
  }
  return value;
}

function date(value: unknown, path: string): string {
  const candidate = text(value, path, 10);
  if (!DATE_PATTERN.test(candidate)) {
    throw new TypeError(`${path} is not an ISO date`);
  }
  const parsed = Date.parse(`${candidate}T00:00:00.000Z`);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString().slice(0, 10) !== candidate) {
    throw new TypeError(`${path} is not a calendar date`);
  }
  return candidate;
}

function timestamp(value: unknown, path: string): string {
  const candidate = text(value, path, 64);
  const parsed = Date.parse(candidate);
  if (!Number.isFinite(parsed)) {
    throw new TypeError(`${path} is not a timestamp`);
  }
  return new Date(parsed).toISOString();
}

function cve(value: unknown, path: string): string {
  const candidate = text(value, path, 32).toUpperCase();
  if (!CVE_PATTERN.test(candidate)) {
    throw new TypeError(`${path} is not a canonical CVE identifier`);
  }
  return candidate;
}

function ransomwareUse(value: unknown, path: string): CisaKevRansomwareUse {
  if (value === "Known") {
    return "known";
  }
  if (value === "Unknown") {
    return "unknown";
  }
  throw new TypeError(`${path} is invalid`);
}

function cwes(value: unknown, path: string): readonly string[] {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (
    !Array.isArray(value) ||
    value.length > CISA_KEV_LIMITS.maximumCwesPerEntry
  ) {
    throw new TypeError(`${path} is invalid`);
  }
  const unique = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const candidate = text(value[index], `${path}[${index.toString()}]`, 32).toUpperCase();
    if (!CWE_PATTERN.test(candidate)) {
      throw new TypeError(`${path} contains an invalid CWE identifier`);
    }
    unique.add(candidate);
  }
  return Object.freeze([...unique].sort());
}

function normalizeEntry(value: unknown, index: number): CisaKevEntry {
  const path = `vulnerabilities[${index.toString()}]`;
  const record = assertSafeRecord(value, path);
  return Object.freeze({
    cveId: cve(record.cveID, `${path}.cveID`),
    vendorProject: text(
      record.vendorProject,
      `${path}.vendorProject`,
      CISA_KEV_LIMITS.maximumShortStringLength,
    ),
    product: text(
      record.product,
      `${path}.product`,
      CISA_KEV_LIMITS.maximumShortStringLength,
    ),
    vulnerabilityName: text(
      record.vulnerabilityName,
      `${path}.vulnerabilityName`,
      CISA_KEV_LIMITS.maximumShortStringLength,
    ),
    dateAdded: date(record.dateAdded, `${path}.dateAdded`),
    dueDate: date(record.dueDate, `${path}.dueDate`),
    requiredAction: text(record.requiredAction, `${path}.requiredAction`),
    ransomwareUse: ransomwareUse(
      record.knownRansomwareCampaignUse,
      `${path}.knownRansomwareCampaignUse`,
    ),
    cwes: cwes(record.cwes, `${path}.cwes`),
  });
}

function sameEntry(left: CisaKevEntry, right: CisaKevEntry): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function normalizeCisaKevCatalog(
  value: unknown,
  fetchedAt: string,
): CisaKevCatalog {
  const root = assertSafeRecord(value, "catalog");
  const rawEntries = root.vulnerabilities;
  if (
    !Array.isArray(rawEntries) ||
    rawEntries.length > CISA_KEV_LIMITS.maximumEntries
  ) {
    throw new TypeError("catalog.vulnerabilities is invalid");
  }
  if (
    typeof root.count !== "number" ||
    !Number.isSafeInteger(root.count) ||
    root.count !== rawEntries.length
  ) {
    throw new TypeError("catalog.count does not match the catalog entries");
  }

  const entries = new Map<string, CisaKevEntry>();
  for (let index = 0; index < rawEntries.length; index += 1) {
    const entry = normalizeEntry(rawEntries[index], index);
    const existing = entries.get(entry.cveId);
    if (existing !== undefined && !sameEntry(existing, entry)) {
      throw new TypeError("catalog contains conflicting duplicate CVE entries");
    }
    entries.set(entry.cveId, entry);
  }
  const normalizedEntries = [...entries.values()].sort((left, right) =>
    left.cveId.localeCompare(right.cveId),
  );
  Object.freeze(normalizedEntries);
  return Object.freeze({
    schemaVersion: 1,
    source: "CISA KEV",
    catalogVersion: text(root.catalogVersion, "catalog.catalogVersion", 128),
    releasedAt: timestamp(root.dateReleased, "catalog.dateReleased"),
    fetchedAt: timestamp(fetchedAt, "fetchedAt"),
    entries: normalizedEntries,
  });
}

export function isCisaKevCatalog(value: unknown): value is CisaKevCatalog {
  try {
    const record = assertSafeRecord(value, "catalog");
    if (
      record.schemaVersion !== 1 ||
      record.source !== "CISA KEV" ||
      typeof record.catalogVersion !== "string" ||
      typeof record.releasedAt !== "string" ||
      typeof record.fetchedAt !== "string" ||
      !Array.isArray(record.entries) ||
      record.entries.length > CISA_KEV_LIMITS.maximumEntries
    ) {
      return false;
    }
    timestamp(record.releasedAt, "catalog.releasedAt");
    timestamp(record.fetchedAt, "catalog.fetchedAt");
    text(record.catalogVersion, "catalog.catalogVersion", 128);
    const seen = new Set<string>();
    for (let index = 0; index < record.entries.length; index += 1) {
      const entry = assertSafeRecord(record.entries[index], `entries[${index.toString()}]`);
      const cveId = cve(entry.cveId, `entries[${index.toString()}].cveId`);
      if (entry.cveId !== cveId) {
        return false;
      }
      if (seen.has(cveId)) {
        return false;
      }
      seen.add(cveId);
      text(entry.vendorProject, "entry.vendorProject", CISA_KEV_LIMITS.maximumShortStringLength);
      text(entry.product, "entry.product", CISA_KEV_LIMITS.maximumShortStringLength);
      text(entry.vulnerabilityName, "entry.vulnerabilityName", CISA_KEV_LIMITS.maximumShortStringLength);
      date(entry.dateAdded, "entry.dateAdded");
      date(entry.dueDate, "entry.dueDate");
      text(entry.requiredAction, "entry.requiredAction");
      if (entry.ransomwareUse !== "known" && entry.ransomwareUse !== "unknown") {
        return false;
      }
      cwes(entry.cwes, "entry.cwes");
    }
    return true;
  } catch {
    return false;
  }
}
