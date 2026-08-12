import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  describeError,
  sanitizeDisplayValue,
  sanitizeLogValue,
} from "../services/Logger";

void test("sanitizes multiline, control, separator, and bidi content", () => {
  const value = "workspace\r\n\t\u001b[31m\u0085\u2028\u202Espoof";

  assert.equal(
    sanitizeLogValue(value),
    "workspace\\r\\n\\t�[31m���spoof",
  );
  assert.equal(sanitizeDisplayValue(value), "workspace   �[31m���spoof");
});

void test("bounds hostile log and display values", () => {
  assert.equal(sanitizeLogValue("a".repeat(5_000)).length, 4_097);
  assert.equal(sanitizeDisplayValue("a".repeat(500)).length, 161);
  assert.equal(sanitizeLogValue(`${"a".repeat(4_095)}😀`).endsWith("�"), false);
});

void test("does not copy provider messages or sensitive URIs into error logs", () => {
  const error = Object.assign(
    new Error("failed at vscode-remote://user:secret@host/path?token=secret"),
    { name: "FileSystemError", code: "FileNotFound" },
  );

  assert.equal(describeError(error), "FileSystemError (FileNotFound)");
});
