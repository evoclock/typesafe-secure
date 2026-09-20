// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TypeSafe AI.

/**
 * Exception-safe string coercion for the never-throw contract (SPEC A2.7a).
 *
 * - `null`/`undefined` are treated as the empty string.
 * - Symbols are treated as the empty string (`String(symbol)` throws).
 * - Any value whose string coercion throws is treated as the empty string.
 *
 * This helper itself never throws.
 */
export function safeCoerceString(input: unknown): string {
  if (input === null || input === undefined) {
    return "";
  }
  if (typeof input === "symbol") {
    return "";
  }
  try {
    return String(input);
  } catch {
    return "";
  }
}
