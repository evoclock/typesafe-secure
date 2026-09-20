// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TypeSafe AI.

/**
 * PEM private-key block handling (SPEC.md A4 row 16).
 *
 * Implemented as a linear cursor walk instead of a lazy dot-all regex so the
 * cost stays O(n) even for adversarial inputs containing many unterminated
 * `-----BEGIN` headers (A5.2a bounded-time requirement). The walk reproduces
 * the lazy-regex semantics: the earliest valid BEGIN header pairs with the
 * nearest following valid END header; an unterminated header survives
 * (documented accepted risk, A4 row 16).
 */

const BEGIN_HEADER = /-----BEGIN [A-Z ]*PRIVATE KEY-----/y;
const END_HEADER = /-----END [A-Z ]*PRIVATE KEY-----/y;

export interface PemWalkResult {
  /** Text with every complete block replaced by the marker (or the input unchanged). */
  readonly text: string;
  /** True iff at least one complete block was found. */
  readonly found: boolean;
}

export function walkPrivateKeyBlocks(text: string): PemWalkResult {
  let result = "";
  let cursor = 0;
  let found = false;
  for (;;) {
    const beginIdx = text.indexOf("-----BEGIN", cursor);
    if (beginIdx < 0) {
      break;
    }
    BEGIN_HEADER.lastIndex = beginIdx;
    if (BEGIN_HEADER.exec(text) === null) {
      cursor = beginIdx + 1;
      continue;
    }
    const bodyStart = BEGIN_HEADER.lastIndex;
    const endIdx = findValidEnd(text, bodyStart);
    if (endIdx === null) {
      cursor = beginIdx + 1;
      continue;
    }
    found = true;
    result += text.slice(cursor, beginIdx) + "[REDACTED:private_key_block]";
    cursor = endIdx;
  }
  if (!found) {
    return { text, found: false };
  }
  result += text.slice(cursor);
  return { text: result, found: true };
}

function findValidEnd(text: string, from: number): number | null {
  let searchFrom = from;
  for (;;) {
    const idx = text.indexOf("-----END", searchFrom);
    if (idx < 0) {
      return null;
    }
    END_HEADER.lastIndex = idx;
    if (END_HEADER.exec(text) !== null) {
      return END_HEADER.lastIndex;
    }
    searchFrom = idx + 1;
  }
}
