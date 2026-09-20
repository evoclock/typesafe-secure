// SPDX-License-Identifier: MIT
// Testudo-derived hygiene helper (SPEC A2.5).
//
// stripControls is hygiene, NOT redaction, and is deliberately SEPARATE from
// redactString: the library never applies it implicitly (A2.5). Pre-send
// screening pipelines over untrusted input SHOULD call stripControls BEFORE
// redactString — control characters can smuggle secret shapes past regexes.
//
// Never-throw contract (A2.7a): null/undefined/symbols/throwing coercions
// behave as the empty string.

import { safeCoerceString } from "./coerce.js";

export function stripControls(text: string): string {
  const input = safeCoerceString(text);
  let out = "";
  let i = 0;
  const len = input.length;
  while (i < len) {
    const code = input.charCodeAt(i);
    if (code === 0x1b) {
      const next = i + 1 < len ? input.charCodeAt(i + 1) : -1;
      if (next === 0x5b) {
        // CSI: parameter bytes 0x30-0x3F, intermediates 0x20-0x2F,
        // terminated by a final byte 0x40-0x7E.
        i += 2;
        while (i < len) {
          const c = input.charCodeAt(i);
          i += 1;
          if (c >= 0x40 && c <= 0x7e) break;
        }
        continue;
      }
      if (next === 0x5d) {
        // OSC: terminated by BEL or ST (ESC \).
        i += 2;
        while (i < len) {
          if (input.charCodeAt(i) === 0x07) {
            i += 1;
            break;
          }
          if (input.charCodeAt(i) === 0x1b && i + 1 < len && input.charCodeAt(i + 1) === 0x5c) {
            i += 2;
            break;
          }
          i += 1;
        }
        continue;
      }
      if (next === 0x1b) {
        // ESC ESC: drop only the first ESC; the second starts its own
        // sequence (e.g. "\x1b\x1b[31m" must strip to "x", not "[31m x").
        i += 1;
        continue;
      }
      if (next >= 0x20 && next <= 0x2f) {
        // ESC + intermediates + final byte (e.g. ESC ( B): drop through the
        // final byte 0x30-0x7E.
        i += 2;
        while (i < len) {
          const c = input.charCodeAt(i);
          i += 1;
          if (c >= 0x30 && c <= 0x7e) break;
        }
        continue;
      }
      // Other ESC-initiated forms (e.g. ESC 7): drop the ESC and the single
      // following byte. A lone trailing ESC is dropped.
      i += next >= 0x00 ? 2 : 1;
      continue;
    }
    if (code === 0x0a || code === 0x09) {
      out += input.charAt(i);
      i += 1;
      continue;
    }
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      // Remaining C0 (including CR), DEL, and C1 bytes are removed.
      i += 1;
      continue;
    }
    out += input.charAt(i);
    i += 1;
  }
  return out;
}
