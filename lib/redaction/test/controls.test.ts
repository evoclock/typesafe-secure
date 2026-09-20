// SPDX-License-Identifier: MIT
// stripControls coverage (A5.9): CSI/OSC/other ESC sequences removed, \n and
// \t preserved, \r and C1 bytes removed, input never mutated (strings are
// immutable; purity is asserted by comparing against a captured snapshot).
import { test } from "node:test";
import assert from "node:assert/strict";
import { stripControls } from "../src/index.js";
const asText = (v: unknown): string => v as string; // never-throw probes pass hostile inputs through the declared string signature


test("A5.9 CSI sequences are removed", () => {
  assert.equal(stripControls("a\x1b[31mred\x1b[0mb"), "aredb");
  assert.equal(stripControls("\x1b[1;42mK\x1b[m"), "K");
  assert.equal(stripControls("\x1b[?25l\x1b[2J\x1b[Hx"), "x");
});

test("A5.9 OSC sequences are removed (BEL and ST terminators)", () => {
  assert.equal(stripControls("a\x1b]0;title\x07b"), "ab");
  assert.equal(stripControls("a\x1b]8;;http://x\x1b\\b"), "ab");
});

test("A5.9 other ESC-initiated sequences and lone ESC are removed", () => {
  assert.equal(stripControls("a\x1b(Bb"), "ab");
  assert.equal(stripControls("a\x1b"), "a");
  assert.equal(stripControls("\x1b\x1b[31mx"), "x");
});

test("A5.9 newline and tab are preserved; CR, C0, DEL, C1 removed", () => {
  assert.equal(stripControls("l1\r\nl2\tend"), "l1\nl2\tend");
  assert.equal(stripControls("a\x00\x01\x07\x08\x0b\x0cb"), "ab");
  assert.equal(stripControls("a\x7f\x85\x9fb"), "ab");
});

test("A5.9 benign text passes through unchanged", () => {
  const text = "keep  spacing\tand\nnewlines — ünïcödé ✓";
  assert.equal(stripControls(text), text);
});

test("A5.9 stripControls never throws and coerces per A2.7a", () => {
  assert.equal(stripControls(asText(null)), "");
  assert.equal(stripControls(asText(undefined)), "");
  assert.equal(stripControls(asText(42)), "42");
  assert.equal(stripControls(asText({})), "[object Object]");
  const hostile = { [Symbol.toPrimitive]() { throw new Error("no"); } };
  assert.equal(stripControls(asText(hostile)), "");
  assert.equal(stripControls(asText(Symbol("s"))), "");
});
