// SPDX-License-Identifier: MIT
// Core redaction API (SPEC.md A2.1–A2.4, A3.x).
//
// NOT data-loss prevention (DLP). One bounded, best-effort layer; markers are
// UNAUTHENTICATED and MUST NOT be treated as a trust signal (A1.2/OQ-5).
//
// Binding invariants implemented here:
// - unconditional by construction; no disable knob exists in any form (A3.1);
// - all-type sensitive-key drop (A3.2);
// - purity: no I/O, no env, no randomness; inputs never mutated (A3.3);
// - prototype-safe copying via Object.create(null) + defineProperty (A3.3a);
// - MAX_DEPTH = 32 internal constant, root depth 0, fail-closed
//   [REDACTED:depth_limit]; cycle guard -> [REDACTED:cycle]; internal-slot
//   containers, functions and symbols -> [REDACTED:opaque] (A3.4/OQ-4);
// - never-throw on any input (A2.7a); hostile getter/Proxy reads fail closed;
// - marker terminality: emitted markers never re-match any rule (A3.6a).

import { safeCoerceString } from "./coerce.js";
import {
  STRING_RULES,
  applyCardMasking,
  cardDetected,
  type StringRule,
} from "./rules.js";
import { isSensitiveKey } from "./keys.js";

export { SENSITIVE_KEYS, isSensitiveKey } from "./keys.js";

/** Internal constant; NOT a parameter and never exposed (A3.4/A3.1). */
const MAX_DEPTH = 32;

const MARKER_SENSITIVE_KEY = "[REDACTED:sensitive_key]";
const MARKER_DEPTH_LIMIT = "[REDACTED:depth_limit]";
const MARKER_CYCLE = "[REDACTED:cycle]";
const MARKER_OPAQUE = "[REDACTED:opaque]";

function isOpaqueContainer(value: object): boolean {
  return (
    value instanceof Map ||
    value instanceof Set ||
    value instanceof WeakMap ||
    value instanceof WeakSet ||
    value instanceof Date ||
    value instanceof RegExp ||
    value instanceof Promise ||
    value instanceof Error ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value)
  );
}

function walk(value: unknown, depth: number, seen: Set<object>): unknown {
  // Subtrees AT MAX_DEPTH are replaced wholesale; their children are never
  // traversed (A3.4 threshold, fail closed).
  if (depth >= MAX_DEPTH) return MARKER_DEPTH_LIMIT;
  if (value === null) return null;
  const kind = typeof value;
  if (kind === "string") return redactString(value as string);
  if (kind === "number" || kind === "boolean" || kind === "bigint") return value;
  if (kind === "undefined") return undefined;
  if (kind === "symbol" || kind === "function") return MARKER_OPAQUE;

  const obj = value as object;
  if (seen.has(obj)) return MARKER_CYCLE;
  if (isOpaqueContainer(obj)) return MARKER_OPAQUE;

  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      const length = obj.length;
      const out: unknown[] = new Array(length);
      for (let i = 0; i < length; i += 1) {
        let child: unknown;
        try {
          child = obj[i];
        } catch {
          child = MARKER_OPAQUE;
        }
        out[i] = walk(child, depth + 1, seen);
      }
      return out;
    }
    let keys: string[];
    try {
      keys = Object.keys(obj);
    } catch {
      // e.g. a Proxy whose ownKeys trap throws: fail closed.
      return MARKER_OPAQUE;
    }
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      let child: unknown;
      try {
        child = (obj as Record<string, unknown>)[key];
      } catch {
        // Hostile getter / throwing Proxy get trap: fail closed (A2.7a).
        child = MARKER_OPAQUE;
      }
      const stored = isSensitiveKey(key)
        ? MARKER_SENSITIVE_KEY
        : walk(child, depth + 1, seen);
      // Prototype-safe install: own data property on a null-prototype
      // object; "__proto__" can never reach Object.prototype (A3.3a).
      Object.defineProperty(out, key, {
        value: stored,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  } finally {
    seen.delete(obj);
  }
}

/**
 * Recursive, unconditional redaction of objects, arrays, and strings
 * (A2.1). Returns NEW structures; the input is never mutated (A3.3).
 * Never throws (A2.7a).
 */
export function redactValue(value: unknown): unknown {
  try {
    return walk(value, 0, new Set());
  } catch {
    // Absolute fail-closed backstop: bounded, auditable loss, never a crash.
    return MARKER_OPAQUE;
  }
}

function applyRules(text: string): string {
  let out = text;
  for (const rule of STRING_RULES) {
    out = rule.apply(out);
  }
  // credit_card (row 25): masks in place, never emits a marker (A2.2).
  return applyCardMasking(out);
}

/**
 * Ordered rule application over text (A2.2). Non-string input is coerced
 * per A2.7a (null/undefined/symbols/throwing coercions -> ""). Never
 * throws. stripControls is NOT applied implicitly (A2.5).
 */
export function redactString(text: string): string {
  const input = safeCoerceString(text);
  try {
    return applyRules(input);
  } catch {
    // Unexpected failure: fail closed rather than leak.
    return "";
  }
}

function detectedTypes(text: string): string[] {
  const input = safeCoerceString(text);
  const ids: string[] = [];
  try {
    // Detection respects rule order and precedence (A3.6, A5.8): each rule
    // is tested against a working copy in which earlier detections have
    // already replaced their matches, so a broader later rule cannot claim
    // text an earlier rule classified (sk-ant-… is anthropic_key, never
    // openai_key). Replaced spans become a placeholder no rule can match.
    // Ids are reported in RULE order (A2.4).
    let working = input;
    for (const rule of STRING_RULES as readonly StringRule[]) {
      const hit = rule.detectFn ? rule.detectFn(working) : rule.detect.test(working);
      if (hit) {
        ids.push(rule.id);
        working = rule.apply(working).replace(/\[REDACTED:[a-z_]+\]/g, "\u0000");
      }
    }
    if (cardDetected(working)) ids.push("credit_card");
  } catch {
    return [];
  }
  return ids;
}

/**
 * Audit view: deduplicated detected rule ids, in rule order. Contains no
 * input values. credit_card is reported when detected even though it is
 * masked rather than marked (A2.4). Never throws.
 */
export function redactionTypes(text: string): string[] {
  return detectedTypes(text);
}

/**
 * Read-only inspection, independent of redaction (A2.3). Agreement with
 * redactionTypes is fixed by construction and tested (A5.7). Never throws.
 */
export function containsSensitive(text: string): boolean {
  return detectedTypes(text).length > 0;
}
