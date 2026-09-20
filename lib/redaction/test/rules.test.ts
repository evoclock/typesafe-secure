// SPDX-License-Identifier: MIT
// Per-rule fixtures and benign lookalikes (SPEC A5.1, A4.2 case pinning).
// All fixtures are SYNTHETIC and visibly fake (A3.5): no fixture may be a
// plausibly-live credential for any real system.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  redactString,
  containsSensitive,
  redactionTypes,
} from "../src/index.js";

import { EXACT } from "./rule-fixtures.js";

const A36 = "A".repeat(36);

test("A5.1 exact per-rule fixtures and benign lookalikes", () => {
  for (const [input, expected] of EXACT) {
    assert.equal(redactString(input), expected, `fixture: ${JSON.stringify(input)}`);
  }
});

test("A5.1 redactionTypes reports exact rule ids in table order", () => {
  assert.deepEqual(redactionTypes("AKIAIOSFODNN7EXAMPLE"), ["aws_access_key"]);
  assert.deepEqual(redactionTypes("4111 1111 1111 1111"), ["credit_card"]);
  assert.deepEqual(redactionTypes("0000 0000 0000 0000"), []);
  assert.deepEqual(redactionTypes("123456789012"), []);
  assert.deepEqual(redactionTypes("plain text here"), []);
  assert.deepEqual(
    redactionTypes(`AKIAIOSFODNN7EXAMPLE and ghp_${A36}`),
    ["aws_access_key", "github_pat_classic"],
  );
});

test("A2.2/A4 row 25 card masking preserves separators and length exactly", () => {
  const before = "card 4111 1111 1111 1111 end";
  const out = redactString(before);
  assert.equal(out, "card •••• •••• •••• •••• end");
  assert.equal(out.length, before.length);
  assert.equal(/[0-9]/.test(out), false);
  assert.equal(out.includes("[REDACTED"), false);
  assert.deepEqual(redactionTypes(before), ["credit_card"]);
});

test("A4 row 25 out-of-gate and malformed grouped runs survive", () => {
  assert.equal(redactString("1234567890 1234"), "1234567890 1234");
  assert.equal(redactString("1234 5678 9012 3456 7890"), "1234 5678 9012 3456 7890");
  assert.equal(redactionTypes("1234 5678 9012 3456 7890").length, 0);
  assert.equal(redactString("12 - 34 - 56 - 78"), "12 - 34 - 56 - 78");
  assert.equal(redactString("12--34--56--78--90"), "12--34--56--78--90");
});

test("A5.7 containsSensitive agrees with redactionTypes on the rule corpus", () => {
  for (const [input] of EXACT) {
    assert.equal(
      containsSensitive(input),
      redactionTypes(input).length > 0,
      `agreement failed for: ${JSON.stringify(input)}`,
    );
  }
});