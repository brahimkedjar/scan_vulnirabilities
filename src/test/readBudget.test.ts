import { strict as assert } from "node:assert";
import { test } from "node:test";

import { ReadBudget } from "../discovery/readBudget";

void test("accepts reads within the aggregate byte budget", () => {
  const budget = new ReadBudget(10);

  assert.equal(budget.tryConsume(4), true);
  assert.equal(budget.tryConsume(6), true);
  assert.equal(budget.tryConsume(0), false);
});

void test("exhausts the budget when a provider underreports a read", () => {
  const budget = new ReadBudget(10);

  assert.equal(budget.tryConsume(2), true);
  assert.equal(budget.tryConsume(9), false);
  assert.equal(budget.tryConsume(1), false);
});

void test("rejects invalid limits and byte counts", () => {
  assert.throws(() => new ReadBudget(0), RangeError);

  const budget = new ReadBudget(10);
  assert.equal(budget.tryConsume(-1), false);
  assert.equal(budget.tryConsume(1), false);
});
