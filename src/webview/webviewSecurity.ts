import { randomBytes } from "node:crypto";

import type { Severity } from "../models/Vulnerability";

const UNSAFE_DISPLAY_CHARACTERS =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu;
const HTML_CHARACTERS = /[&<>"']/gu;
const MAX_ADVISORY_URL_LENGTH = 4_096;

const HTML_ESCAPES: Readonly<Record<string, string>> = Object.freeze({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
});

/**
 * Makes provider-controlled text safe for an HTML text or quoted-attribute
 * context. Bidi formatting and non-printing control characters are replaced to
 * prevent invisible UI spoofing; line breaks and tabs remain readable.
 */
export function escapeHtml(value: string, maximumLength = 1_048_576): string {
  if (typeof value !== "string") {
    return "";
  }
  const bounded =
    value.length <= maximumLength
      ? value
      : `${value.slice(0, Math.max(0, maximumLength - 14))}\n… (truncated)`;
  return bounded
    .replace(UNSAFE_DISPLAY_CHARACTERS, "\uFFFD")
    .replace(HTML_CHARACTERS, (character) => HTML_ESCAPES[character] ?? "");
}

export function normalizeDisplaySeverity(value: unknown): Severity {
  switch (value) {
    case "CRITICAL":
    case "HIGH":
    case "MEDIUM":
    case "LOW":
    case "UNKNOWN":
      return value;
    default:
      return "UNKNOWN";
  }
}

/** Returns a normalized URL only when the provider value is unambiguous HTTPS. */
export function validateHttpsAdvisoryUrl(value: unknown): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ADVISORY_URL_LENGTH ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f\\]/u.test(value) ||
    !/^https:\/\//iu.test(value)
  ) {
    return undefined;
  }

  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname.length === 0 ||
      parsed.username.length > 0 ||
      parsed.password.length > 0
    ) {
      return undefined;
    }
    return parsed.href;
  } catch {
    return undefined;
  }
}

export function advisoryHostname(value: string): string | undefined {
  const validated = validateHttpsAdvisoryUrl(value);
  if (validated === undefined) {
    return undefined;
  }
  return new URL(validated).hostname;
}

export function createWebviewNonce(): string {
  return randomBytes(24).toString("base64url");
}

export function assertWebviewNonce(value: string): string {
  if (!/^[A-Za-z0-9_-]{16,128}$/u.test(value)) {
    throw new Error("The webview nonce is invalid.");
  }
  return value;
}
