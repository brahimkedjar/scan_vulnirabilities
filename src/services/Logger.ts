import type * as vscode from "vscode";

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string, error?: unknown): void;
  show(preserveFocus?: boolean): void;
}

const UNSAFE_TEXT_CHARACTERS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/gu;
const MAX_LOG_MESSAGE_LENGTH = 4_096;
const MAX_DISPLAY_VALUE_LENGTH = 160;

function truncate(value: string, maximumLength: number): string {
  if (value.length <= maximumLength) {
    return value;
  }

  let bounded = value.slice(0, maximumLength);
  const finalCodeUnit = bounded.charCodeAt(bounded.length - 1);
  if (finalCodeUnit >= 0xd800 && finalCodeUnit <= 0xdbff) {
    bounded = bounded.slice(0, -1);
  }
  return `${bounded}…`;
}

export function sanitizeLogValue(value: string): string {
  const boundedInput = value.slice(0, MAX_LOG_MESSAGE_LENGTH + 1);
  return truncate(
    boundedInput
      .replaceAll("\r", "\\r")
      .replaceAll("\n", "\\n")
      .replaceAll("\t", "\\t")
      .replace(UNSAFE_TEXT_CHARACTERS, "�"),
    MAX_LOG_MESSAGE_LENGTH,
  );
}

export function sanitizeDisplayValue(value: string): string {
  const boundedInput = value.slice(0, MAX_DISPLAY_VALUE_LENGTH + 1);
  return truncate(
    boundedInput
      .replaceAll("\r", " ")
      .replaceAll("\n", " ")
      .replaceAll("\t", " ")
      .replace(UNSAFE_TEXT_CHARACTERS, "�"),
    MAX_DISPLAY_VALUE_LENGTH,
  );
}

export function describeError(error: unknown): string {
  if (error instanceof Error) {
    const name = error.name.length > 0 ? error.name : "Error";
    const possibleCode = (error as Error & { readonly code?: unknown }).code;
    const code =
      typeof possibleCode === "string" &&
      /^[0-9A-Za-z_.-]{1,64}$/u.test(possibleCode)
        ? ` (${possibleCode})`
        : "";
    return sanitizeLogValue(`${name}${code}`);
  }
  return "Unknown error";
}

export class OutputChannelLogger implements Logger {
  public constructor(private readonly channel: vscode.OutputChannel) {}

  public info(message: string): void {
    this.write("INFO", message);
  }

  public warn(message: string): void {
    this.write("WARN", message);
  }

  public error(message: string, error?: unknown): void {
    const suffix = error === undefined ? "" : `: ${describeError(error)}`;
    this.write("ERROR", `${message}${suffix}`);
  }

  public show(preserveFocus = true): void {
    this.channel.show(preserveFocus);
  }

  private write(level: "INFO" | "WARN" | "ERROR", message: string): void {
    const timestamp = new Date().toISOString();
    this.channel.appendLine(
      `${timestamp} [${level}] ${sanitizeLogValue(message)}`,
    );
  }
}
