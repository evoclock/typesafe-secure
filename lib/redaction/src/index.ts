// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TypeSafe AI.

/**
 * Public surface of the redaction module (SPEC.md A2, A6.4). Named exports
 * only; no default export; no options objects anywhere in the API (A3.1).
 * Deep imports are not API.
 *
 * NOT data-loss prevention (DLP) — A1.2: pattern/key-based redaction cannot
 * catch unknown or proprietary credential formats, arbitrary proprietary
 * values, semantic secrets, encoded/split/renamed secrets, anything the
 * rule set does not know yet, secrets used as KEY names, or
 * unicode/homoglyph-obfuscated shapes. One layer, not a guarantee. Markers
 * are UNAUTHENTICATED (OQ-5): a literal `[REDACTED:*]` in the input is
 * preserved verbatim and marker presence MUST NOT be treated as a trust
 * signal.
 *
 * Caller obligations (A1.3): minimize state BEFORE calling redaction —
 * minimize → redact → send. When input provenance is untrusted, screening
 * pipelines SHOULD call `stripControls` BEFORE `redactString` (control
 * characters can smuggle secret shapes past regexes); the library never
 * does this implicitly (A2.5).
 */

export {
  redactValue,
  redactString,
  redactionTypes,
  containsSensitive,
  SENSITIVE_KEYS,
  isSensitiveKey,
} from "./redact.js";
export { stripControls } from "./controls.js";
