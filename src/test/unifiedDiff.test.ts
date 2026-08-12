import { strict as assert } from "node:assert";
import { test } from "node:test";

import { createUnifiedDiff } from "../remediation/apply/UnifiedDiff";

void test("unified diff reflects actual minimal changed lines", () => {
  const diff = createUnifiedDiff(
    "package.json",
    '{\r\n  "lodash": "^4.17.20"\r\n}\r\n',
    '{\r\n  "lodash": "^4.17.21"\r\n}\r\n',
  );
  assert.match(diff ?? "", /^--- package\.json\n\+\+\+ package\.json/mu);
  assert.match(diff ?? "", /-  "lodash": "\^4\.17\.20"/u);
  assert.match(diff ?? "", /\+  "lodash": "\^4\.17\.21"/u);
});

void test("unified diff sanitizes controls and rejects oversized previews", () => {
  assert.doesNotMatch(
    createUnifiedDiff("evil\u202E", "a\u001b", "b") ?? "",
    /[\u001b\u202e]/u,
  );
  assert.equal(createUnifiedDiff("x", "a".repeat(300_000), "b".repeat(300_000)), undefined);
});
