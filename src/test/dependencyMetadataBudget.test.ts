import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  consumeDependencyMetadataBytes,
  registerDependencyMetadataBudget,
} from "../package-managers/dependencyMetadataBudget";

void test("shares and saturates one dependency-metadata budget per scan", () => {
  const signal = new AbortController().signal;
  const registration = registerDependencyMetadataBudget(signal, 10);
  const nestedRegistration = registerDependencyMetadataBudget(signal, 999);
  try {
    assert.equal(consumeDependencyMetadataBytes(signal, 6), true);
    assert.equal(consumeDependencyMetadataBytes(signal, 4), true);
    assert.equal(consumeDependencyMetadataBytes(signal, 0), false);
    assert.equal(consumeDependencyMetadataBytes(signal, 1), false);
  } finally {
    nestedRegistration.dispose();
    registration.dispose();
  }

  assert.equal(consumeDependencyMetadataBytes(signal, 11), true);
});

void test("invalid byte counts fail closed without affecting unregistered reads", () => {
  const signal = new AbortController().signal;
  const registration = registerDependencyMetadataBudget(signal, 10);
  try {
    assert.equal(consumeDependencyMetadataBytes(signal, -1), false);
    assert.equal(consumeDependencyMetadataBytes(signal, 1), false);
  } finally {
    registration.dispose();
  }

  assert.equal(consumeDependencyMetadataBytes(undefined, Number.NaN), true);
});
