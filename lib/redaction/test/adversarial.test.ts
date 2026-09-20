// SPDX-License-Identifier: MIT
// Adversarial input classes (A5.2a, N4) and never-throw coverage (A5.10a).
// All fixtures synthetic (A3.5).
import { test } from "node:test";
import assert from "node:assert/strict";
const asText = (v: unknown): string => v as string; // never-throw probes pass hostile inputs through the declared string signature

import {
  redactValue,
  redactString,
  containsSensitive,
  redactionTypes,
  stripControls,
  SENSITIVE_KEYS,
  isSensitiveKey,
} from "../src/index.js";

const FIVE: readonly ((...args: unknown[]) => unknown)[] = [
  (v) => redactString(v as string),
  (v) => containsSensitive(v as string),
  (v) => redactionTypes(v as string),
  (v) => stripControls(v as string),
  (v) => redactValue(v),
];

const BIG = 100_000;

test("A5.2a long inputs complete in bounded time against every rule family", () => {
  const cases: string[] = [
    "AKIA".repeat(BIG / 4),
    "ghp_" + "a".repeat(BIG),
    "sk-ant-" + "x".repeat(BIG),
    "x".repeat(BIG) + "@example.com",
    "password: ".repeat(BIG / 10),
    "-----BEGIN PRIVATE KEY-----".repeat(BIG / 27),
    "eyJ" + "A.".repeat(BIG / 2),
    "https://".repeat(BIG / 8),
    "MERGE_GATEWAY_API_KEY=".repeat(BIG / 22),
    "<".repeat(BIG),
    "=".repeat(BIG),
    `xapp-1${"-".repeat(BIG)}`,
    "a.a.a.a.".repeat(BIG / 8) + "@",
  ];
  const budgetMs = 5_000;
  for (const input of cases) {
    const start = performance.now();
    const out = redactString(input);
    const elapsed = performance.now() - start;
    assert.equal(typeof out, "string");
    assert.ok(elapsed < budgetMs, `too slow: ${elapsed.toFixed(0)}ms`);
  }
});

test("A5.2a 10^5 alternating digits and spaces complete in bounded time", () => {
  let input = "";
  for (let i = 0; i < BIG / 2; i += 1) input += (i % 10) + (i % 2 === 0 ? " " : "");
  const start = performance.now();
  const out = redactString(input);
  const elapsed = performance.now() - start;
  assert.equal(typeof out, "string");
  assert.ok(elapsed < 5_000, `too slow: ${elapsed.toFixed(0)}ms`);
  // A5.2a requires bounded TIME for this input class (no catastrophic
  // backtracking), not a particular masking outcome: row 25's 13–19-digit
  // gate applies to a matched card-shaped window, and this stream contains
  // such windows (e.g. 19-digit runs of 1–2-digit groups), so masking here
  // is shape-conformant. Length preservation is the invariant asserted.
  assert.equal(out.length, input.length);
});

test("A5.2a long digit/space runs with card-shaped groups complete in bounded time", () => {
  const group = "1234 5678 9012 3456 ";
  const input = group.repeat(BIG / group.length);
  const start = performance.now();
  const out = redactString(input);
  const elapsed = performance.now() - start;
  assert.ok(elapsed < 5_000, `too slow: ${elapsed.toFixed(0)}ms`);
  assert.equal(typeof out, "string");
  assert.equal(out.length, input.length);
});

test("A5.2a unicode/homoglyph secret shapes survive (documented cannot-catch)", () => {
  // Cyrillic 'а' in the key name: key rule and assigned-secret rule stay ASCII.
  const homoglyph = "\u0430pi_key: abcdefgh";
  assert.equal(redactString(homoglyph), homoglyph);
  assert.deepEqual(redactionTypes(homoglyph), []);
  const obj = JSON.parse('{"\\u0430pi_key":"abcdefgh"}') as Record<string, unknown>;
  const out = redactValue(obj) as Record<string, unknown>;
  assert.equal(out["\u0430pi_key"], "abcdefgh");
  // Unicode digit lookalikes inside a pan-shaped run: ASCII-only digit class.
  const fakePan = "4111 ١١١١ 1111 1111"; // Arabic-Indic digits in the middle
  assert.equal(redactString(fakePan), fakePan);
  // Unicode digits are not redacted as ssn either.
  assert.equal(redactString("١٢٣-٤٥-٦٧٨٩"), "١٢٣-٤٥-٦٧٨٩");
});

test("A5.2a spoofed/unauthenticated markers pass through and re-match nothing", () => {
  assert.equal(redactString("[REDACTED:fake]"), "[REDACTED:fake]");
  assert.deepEqual(redactionTypes("[REDACTED:fake]"), []);
  assert.equal(containsSensitive("[REDACTED:fake]"), false);
  for (const marker of [
    "[REDACTED:openai_key]",
    "[REDACTED:env_var_assignment]",
    "[REDACTED:sensitive_key]",
    "[REDACTED:credit_card]",
  ]) {
    assert.equal(redactString(marker), marker, marker);
    assert.deepEqual(redactionTypes(marker), [], marker);
  }
  const tree = { note: "[REDACTED:fake]" };
  const out = redactValue(tree) as Record<string, unknown>;
  assert.equal(out.note, "[REDACTED:fake]");
});

test("A5.10a every export survives null/undefined/wrong types per A2.7a", () => {
  // strings
  assert.equal(redactString(asText(null)), "");
  assert.equal(redactString(asText(undefined)), "");
  assert.equal(containsSensitive(asText(null)), false);
  assert.equal(containsSensitive(asText(undefined)), false);
  assert.deepEqual(redactionTypes(asText(null)), []);
  assert.deepEqual(redactionTypes(asText(undefined)), []);
  assert.equal(stripControls(asText(null)), "");
  assert.equal(stripControls(asText(undefined)), "");
  // wrong types coerce via String()
  assert.equal(redactString(asText(12345)), "12345");
  assert.equal(redactString(asText(true)), "true");
  assert.equal(stripControls(asText(12345)), "12345");
  assert.deepEqual(redactionTypes(asText(12345)), []);
  assert.equal(containsSensitive(asText({})), false);
  assert.deepEqual(redactionTypes(asText([1, 2])), []);
  assert.equal(redactString(asText([1, 2])), "1,2");
  // symbols and throwing coercions -> ""
  assert.equal(redactString(asText(Symbol("s"))), "");
  assert.equal(containsSensitive(asText(Symbol("s"))), false);
  assert.deepEqual(redactionTypes(asText(Symbol("s"))), []);
  assert.equal(stripControls(asText(Symbol("s"))), "");
  const hostile = { [Symbol.toPrimitive]() { throw new Error("no"); } };
  assert.equal(redactString(asText(hostile)), "");
  assert.equal(containsSensitive(asText(hostile)), false);
  assert.deepEqual(redactionTypes(asText(hostile)), []);
  assert.equal(stripControls(asText(hostile)), "");
  // redactValue: all of the above, no throw
  for (const input of [null, undefined, 12345, true, {}, [], Symbol("s"), hostile]) {
    assert.doesNotThrow(() => redactValue(input));
  }
  assert.equal(redactValue(null), null);
  assert.equal(redactValue(12345), 12345);
  assert.equal(redactValue("sk-" + "q".repeat(25)), "[REDACTED:openai_key]");
});

test("A5.10a redactValue never throws on exotic inputs", () => {
  const exotic: unknown[] = [
    new Date(0),
    /x/g,
    new Map([[{ toJSON() { throw new Error("no"); } }, 1]]),
    new Set(),
    Promise.resolve(1),
    BigInt(123),
  ];
  for (const input of exotic) {
    assert.doesNotThrow(() => redactValue(input));
  }
  assert.equal(redactValue(new Date(0)), "[REDACTED:opaque]");
  assert.equal(redactValue(Promise.resolve(1)), "[REDACTED:opaque]");
});

test("A2.6 closed registry: exact contents and exact-match variant policy", () => {
  assert.deepEqual([...SENSITIVE_KEYS].sort(), [
    "access_token", "api_key", "apikey", "authorization", "client_secret",
    "credentials", "passwd", "password", "private_key", "pwd", "refresh_token",
    "secret", "token",
  ]);
  assert.equal(isSensitiveKey("password"), true);
  assert.equal(isSensitiveKey("PASSWORD"), true);
  assert.equal(isSensitiveKey("Passwd"), true);
  assert.equal(isSensitiveKey("API-Key"), true);
  assert.equal(isSensitiveKey("refresh_token"), true);
  assert.equal(isSensitiveKey("credentials"), true);
  assert.equal(isSensitiveKey("credential"), false);
  assert.equal(isSensitiveKey("tokenizer"), false);
  assert.equal(isSensitiveKey("password_hint"), false);
  assert.equal(isSensitiveKey("secret_sauce"), false);
  assert.equal(isSensitiveKey("user_password"), false);
  assert.equal(isSensitiveKey("keys"), false);
  assert.equal(isSensitiveKey("xpassword"), false);
  assert.equal(isSensitiveKey("password2"), false);
});

test("A4.E1/E2 excluded forms: IPv4, IPv6, MAC, phone numbers survive", () => {
  // IPv4 (version-number lookalike included), IPv6, MAC, E.164/prose phones.
  const forms = [
    "192.168.1.1",
    "1.2.3.4",
    "10.0.0.255",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "fe80::1",
    "00:1A:2B:3C:4D:5E",
    "00-1a-2b-3c-4d-5e",
    "+1-555-0100",
    "(555) 123-4567",
    "call 555-0100 ext 12",
  ];
  for (const form of forms) {
    assert.equal(redactString(form), form, `excluded form altered: ${form}`);
    assert.deepEqual(redactionTypes(form), [], form);
    assert.equal(containsSensitive(form), false, form);
  }
  // A phone-fragment-shaped run next to a card-gate boundary stays phone.
  assert.equal(redactString("123-456-7890"), "123-456-7890");
  // Inside a value tree the excluded forms also survive.
  const out = redactValue({ note: "server 192.168.1.1 up", mac: "00:1A:2B:3C:4D:5E" }) as Record<string, unknown>;
  assert.equal(out.note, "server 192.168.1.1 up");
  assert.equal(out.mac, "00:1A:2B:3C:4D:5E");
});

test("A5.2a deep arrays beyond MAX_DEPTH yield depth_limit at the same threshold", () => {
  let v: unknown = "leaf";
  for (let i = 0; i < 40; i += 1) v = [v];
  const out = redactValue(v);
  let w = out;
  let depth = 0;
  while (Array.isArray(w)) {
    w = (w as unknown[])[0];
    depth += 1;
  }
  assert.ok(depth <= 33, `traversal exceeded depth budget: ${depth}`);
  assert.equal(w, "[REDACTED:depth_limit]");
});

test("A3.3 purity: stripControls and redactString never mutate their input", () => {
  const before = "keep \x1b[31mme\r\nsafe\t4111 1111 1111 1111";
  const snapshot = before;
  void stripControls(before);
  void redactString(before);
  assert.equal(before, snapshot);
});

test("A2.5 documented composition: stripControls BEFORE redactString (caller opt-in)", () => {
  // A control character must not be able to smuggle a secret shape past
  // screening; the documented pipeline strips controls first.
  const smuggled = "password:\tabc\x08defghij"; // \x08 backspace inside value
  const screened = redactString(stripControls(smuggled));
  assert.ok(!screened.includes("abcdefghij"), screened);
  // The library itself does NOT strip implicitly (A2.5): raw redactString
  // leaves the control character and the (short) value untouched here.
  const raw = redactString(smuggled);
  assert.equal(raw, smuggled);
});
