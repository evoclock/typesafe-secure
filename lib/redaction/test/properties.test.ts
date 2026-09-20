// SPDX-License-Identifier: MIT
// Cross-cutting properties: A5.8 ordering/precedence/idempotence (both
// directions), A5.6 secret-absence, A5.7 agreement, A5.10 hygiene lint,
// A2.5 stripControls → redactString composition. All fixtures SYNTHETIC.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  redactString,
  containsSensitive,
  redactionTypes,
  stripControls,
} from "../src/index.js";
import { EXACT } from "./rule-fixtures.js";

const Q = "q".repeat(25); // openai-shaped synthetic tail
const SK = `sk-${Q}`;

/** [input, secret-substring that must NOT survive] (A5.6). */
const SECRET_CORPUS: readonly (readonly [string, string])[] = [
  ["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
  [`ghp_${"a".repeat(36)}`, `ghp_${"a".repeat(36)}`],
  [`sk-ant-${"x".repeat(25)}`, `sk-ant-${"x".repeat(25)}`],
  [SK, SK],
  ["xoxb-abcdefghijk", "xoxb-abcdefghijk"],
  [`sk_test_${"z".repeat(30)}`, `sk_test_${"z".repeat(30)}`],
  [
    "1234567890-abcdefghijklmnopqrstuvwwxx012345.apps.googleusercontent.com",
    "abcdefghijklmnopqrstuvwwxx012345.apps.googleusercontent.com",
  ],
  ["-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----", "MIIB"],
  ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2", "SflKxwRJSMeKKF2"],
  ["Authorization: Bearer abc123def456", "abc123def456"],
  ["password: hunter2s3cret", "hunter2s3cret"],
  ['{"apiKey": "synthetic-value-1"}', "synthetic-value-1"],
  ["https://user:pass@example.com/path", "user:pass@example.com"],
  ["ANTHROPIC_API_KEY=sk-abc123", "sk-abc123"],
  ["mail user@example.com now", "user@example.com"],
  ["ssn 123-45-6789 filed", "123-45-6789"],
  // Row 25 masks rather than removes: digits must be GONE.
  ["4111 1111 1111 1111", "4111"],
];

test("A5.6 redacted output contains no secret substring (literal and post-stripControls)", () => {
  for (const [input, secret] of SECRET_CORPUS) {
    const out = redactString(input);
    assert.ok(!out.includes(secret), `leaked in ${JSON.stringify(input)} -> ${JSON.stringify(out)}`);
    const stripped = stripControls(out);
    assert.ok(
      !stripped.includes(secret),
      `leaked after stripControls: ${JSON.stringify(input)}`,
    );
  }
});

test("A5.7 containsSensitive(redactString(t)) === false (markers terminal)", () => {
  for (const [input] of EXACT) {
    const out = redactString(input);
    assert.equal(
      containsSensitive(out),
      false,
      `output re-detects: ${JSON.stringify(input)} -> ${JSON.stringify(out)}`,
    );
  }
  for (const [input] of SECRET_CORPUS) {
    assert.equal(containsSensitive(redactString(input)), false, input);
  }
});

test("A5.8 sk-ant- classifies anthropic_key, never openai_key (both adjacencies)", () => {
  assert.deepEqual(redactionTypes(`sk-ant-${"x".repeat(25)}`), ["anthropic_key"]);
  assert.deepEqual(
    redactionTypes(`sk-ant-${"x".repeat(25)} and ${SK}`),
    ["anthropic_key", "openai_key"],
  );
  assert.deepEqual(
    redactionTypes(`${SK} and sk-ant-${"x".repeat(25)}`),
    ["anthropic_key", "openai_key"], // rule-table order (A2.4), not input order
  );
  // Glued with a separator; glued without one merges into a single
  // anthropic token (the '-' separator is part of the token class).
  const out = redactString(`sk-ant-${"x".repeat(25)} and ${SK}`);
  assert.equal(out, "[REDACTED:anthropic_key] and [REDACTED:openai_key]");
  assert.equal(redactString(`sk-ant-${"x".repeat(25)}${SK}`), "[REDACTED:anthropic_key]");
});

test("A5.8 env-var rule vs provider rule, both directions", () => {
  // Provider-shaped value inside an env assignment: provider rule (row 8)
  // masks the value first; the env rule then cannot re-match the marker.
  assert.equal(
    redactString(`ANTHROPIC_API_KEY=${SK}`),
    "ANTHROPIC_API_KEY=[REDACTED:openai_key]",
  );
  // Env assignment then provider token as separate adjacent values.
  const both = `MERGE_GATEWAY_API_KEY=abc123def456 and ${SK}`;
  const out = redactString(both);
  assert.ok(!out.includes("abc123def456"), out);
  assert.ok(!out.includes(SK), out);
  assert.equal(containsSensitive(out), false);
});

test("A5.8 env-var assignment terminality on its own marker output", () => {
  const marker = "ANTHROPIC_API_KEY=[REDACTED:env_var_assignment]";
  assert.equal(redactString(marker), marker);
  assert.equal(containsSensitive(marker), false);
});

test("A5.8 assigned-secret rule vs provider rule, both directions", () => {
  assert.equal(
    redactString(`password: ${SK}`),
    "password: [REDACTED:openai_key]",
  );
  const out = redactString(`${SK} password: abcdefghij`);
  assert.ok(out.includes("[REDACTED:openai_key]"), out);
  assert.ok(out.includes("[REDACTED:assigned_secret]"), out);
  assert.equal(out.includes("abcdefghij"), false);
  assert.equal(containsSensitive(out), false);
});

test("A5.8 json_credential idempotence on its exact replacement form", () => {
  const once = '{"apiKey": [REDACTED:json_credential]}';
  assert.equal(redactString(once), once);
  assert.equal(containsSensitive(once), false);
});

test("A3.7 idempotence: redactString(redactString(x)) === redactString(x) on the full corpus", () => {
  for (const [input] of EXACT) {
    const once = redactString(input);
    assert.equal(redactString(once), once, `not idempotent: ${JSON.stringify(input)}`);
  }
  for (const [input] of SECRET_CORPUS) {
    const once = redactString(input);
    assert.equal(redactString(once), once, `not idempotent: ${JSON.stringify(input)}`);
  }
});

test("A5.8 determinism: identical inputs yield byte-identical outputs", () => {
  for (const [input] of EXACT) {
    assert.equal(redactString(input), redactString(input));
  }
});

test("A2.5 documented composition: stripControls BEFORE redactString catches control-smuggled shapes", () => {
  const smuggled = "password: abcdef\x1b[0mgh";
  assert.equal(containsSensitive(smuggled), false, "shape hidden by embedded control char");
  const clean = stripControls(smuggled);
  assert.equal(containsSensitive(clean), true);
  assert.ok(!redactString(clean).includes("abcdefgh"), "secret survived composition");
});

test("A5.10 hygiene lint: no fixture is a plausibly-live credential", () => {
  const strings = EXACT.map(([s]) => s).concat(SECRET_CORPUS.map(([s]) => s));
  const awsLike = /\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/;
  for (const s of strings) {
    // Every AWS-shaped fixture must be the visibly-fake EXAMPLE form.
    if (awsLike.test(s)) {
      assert.ok(s.includes("EXAMPLE"), `plausibly-live AWS fixture: ${s}`);
    }
    // No fixture may be a high-entropy hex/base64 blob of realistic length.
    if (/^[A-Za-z0-9+/]{40,}$/.test(s)) {
      assert.fail(`plausibly-live opaque blob fixture: ${s}`);
    }
    // Known live-looking card numbers are forbidden; only 4111… placeholders.
    if (/\b4[0-9]{12,15}\b/.test(s)) {
      assert.ok(/^4111/.test(s), `non-placeholder card fixture: ${s}`);
    }
  }
});
