import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  claimDependencyRecords,
  registerDependencyRecordBudget,
  remainingDependencyRecordCapacity,
} from "../package-managers/dependencyRecordBudget";

void test("shares and partially consumes one dependency-record budget per scan", () => {
  const signal = new AbortController().signal;
  const registration = registerDependencyRecordBudget(signal, 5);
  const nestedRegistration = registerDependencyRecordBudget(signal, 3);
  try {
    assert.deepEqual(claimDependencyRecords(signal, 3), {
      accepted: 3,
      omitted: 0,
      remaining: 2,
    });
    assert.deepEqual(claimDependencyRecords(signal, 4), {
      accepted: 2,
      omitted: 2,
      remaining: 0,
    });
    assert.equal(remainingDependencyRecordCapacity(signal), 0);
  } finally {
    nestedRegistration.dispose();
    registration.dispose();
  }

  assert.equal(remainingDependencyRecordCapacity(signal), undefined);
  assert.deepEqual(claimDependencyRecords(signal, 2), {
    accepted: 2,
    omitted: 0,
    remaining: Number.MAX_SAFE_INTEGER,
  });
});

void test("invalid dependency-record claims fail closed", () => {
  const signal = new AbortController().signal;
  const registration = registerDependencyRecordBudget(signal, 5);
  try {
    assert.deepEqual(claimDependencyRecords(signal, Number.NaN), {
      accepted: 0,
      omitted: 0,
      remaining: 0,
    });
    assert.deepEqual(claimDependencyRecords(signal, 1), {
      accepted: 0,
      omitted: 1,
      remaining: 0,
    });
  } finally {
    registration.dispose();
  }
});
