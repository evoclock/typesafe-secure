// SPDX-License-Identifier: MIT
// Closed sensitive-key registry (SPEC A2.6).
//
// The registry is CLOSED: no extension API, no options, no merging. Growth is
// a versioned, reviewed change (new name + rationale + fixtures + benign
// lookalikes + docs), shipped as a semver-visible release.
//
// Matching policy (normative): case-insensitive; hyphen and underscore
// variants of the same name are equivalent; matching is EXACT on the
// normalized key — substring matches never fire ("tokenizer" and
// "password_hint" are NOT sensitive keys).

const CANONICAL_KEYS: readonly string[] = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "client_secret",
  "private_key",
  "authorization",
  "credentials",
];

/** Normalized registry set. */
const NORMALIZED = new Set(CANONICAL_KEYS.map(normalizeKey));

/** Normalize a candidate key: lowercase, hyphen/underscore variants unified. */
function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_]/g, "_");
}

/** Exported closed registry (canonical names, readonly). */
export const SENSITIVE_KEYS: readonly string[] = CANONICAL_KEYS;

/**
 * The registry's canonical interpretation of "is this key sensitive?".
 * Tests and consumers MUST use this rather than re-deriving matching.
 */
export function isSensitiveKey(key: string): boolean {
  return NORMALIZED.has(normalizeKey(key));
}
