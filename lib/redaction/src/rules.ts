// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TypeSafe AI.

/**
 * Ordered pattern rules implementing SPEC.md A4 (credentials/secrets ONLY).
 *
 * Clean-room implementation from the normative Shape column of A4 only: no
 * AGPL source expression (regex literals, comments, or structure) is copied
 * from Janus/Testudo/Hillstar, and no Warp-derived regex expression is
 * copied verbatim (A4.0a).
 *
 * The table order (A4.1) is the application order (A3.6): earlier rules'
 * replacements are visible to later rules. Marker text is terminal
 * (A3.6a): no rule matches, alters, or re-emits any `[REDACTED:*]` output
 * form. The `credit_card` rule masks digits in place and NEVER emits a
 * marker (A2.2); it is applied last (row 25 position) by the pipeline.
 *
 * Every rule is implemented so that matching cost stays bounded on
 * adversarial inputs (A5.2a): no nested unbounded quantifiers, and linear
 * scanners for the two shapes where a naive regex would backtrack
 * (private_key_block walk; credit_card run scan).
 */

import { safeCoerceString } from "./coerce.js";
import { walkPrivateKeyBlocks } from "./pem.js";

/** Result of applying one rule to a full string. */
export interface RuleApplication {
  readonly text: string;
  readonly fired: boolean;
}

export interface StringRule {
  /** Stable marker id (A2.7 vocabulary). */
  readonly id: string;
  /** Detection form (also the audit view used by the inspection API). */
  readonly detect: RegExp;
  /** Optional exact detector used instead of `detect` for the audit view. */
  readonly detectFn?: (text: string) => boolean;
  /** Apply the rule to the whole string; return the new text. */
  apply(text: string): string;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Token character class used by rows 18/19/22 values (SPEC A4 rows 18/19/22). */
const TOKEN_CHARS = "[A-Za-z0-9._~+/=-]";

/**
 * Word boundaries. A marker opening bracket `[` is not a word character, so
 * these also keep rules from matching text glued to marker output.
 */
const WB = "(?![A-Za-z0-9_])";
const WB_START = "(?<![A-Za-z0-9_])";

function regexRule(
  id: string,
  source: string,
  flags: string,
  replace?: (match: string, p1: string | undefined) => string,
): StringRule {
  const detect = new RegExp(source, flags);
  const global = new RegExp(source, flags + "g");
  return {
    id,
    detect,
    apply(text: string): string {
      return text.replace(global, (match: string, p1: string | undefined) =>
        replace === undefined ? `[REDACTED:${id}]` : replace(match, p1),
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Rows 1–17 (case-sensitive shapes, A4.2)
// ---------------------------------------------------------------------------

const AWS_PREFIXES = [
  "AKIA", "A3T", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA",
].join("|");

const B64URL_TAIL = "[A-Za-z0-9_]";

const rules: StringRule[] = [
  // 1. aws_access_key — prefix family + exactly 16 chars [A-Z0-9], word-bounded
  regexRule(
    "aws_access_key",
    `${WB_START}(?:${AWS_PREFIXES})[A-Z0-9]{16}${WB}`,
    "",
  ),

  // 2–6. GitHub PAT family
  regexRule("github_pat_classic", `${WB_START}ghp_${B64URL_TAIL}{36,}${WB}`, ""),
  regexRule("github_pat_fine_grained", `${WB_START}github_pat_${B64URL_TAIL}{82,}`, ""),
  regexRule("github_oauth_token", `${WB_START}gho_${B64URL_TAIL}{36,}${WB}`, ""),
  regexRule("github_user_to_server", `${WB_START}ghu_${B64URL_TAIL}{36,}${WB}`, ""),
  regexRule("github_server_to_server", `${WB_START}ghs_${B64URL_TAIL}{36,}${WB}`, ""),

  // 7. anthropic_key — ordered BEFORE openai_key (A3.6)
  regexRule("anthropic_key", `${WB_START}sk-ant-[A-Za-z0-9_-]{20,}${WB}`, ""),

  // 8. openai_key
  regexRule("openai_key", `${WB_START}sk-[A-Za-z0-9_-]{20,}${WB}`, ""),

  // 9. fireworks_key — fw_ + ≥10 [A-Za-z0-9]
  regexRule("fireworks_key", `${WB_START}fw_[A-Za-z0-9]{10,}${WB}`, ""),

  // 10. google_api_key — AIza + exactly 35 [0-9A-Za-z_-] (39-char shape)
  regexRule("google_api_key", `${WB_START}AIza[0-9A-Za-z_-]{35}${WB}`, ""),

  // 11. google_oauth_id — digits '-' + 32 [0-9A-Za-z_] + .apps.googleusercontent.com
  regexRule(
    "google_oauth_id",
    `${WB_START}[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
    "",
  ),

  // 12. slack_token — xox + {a,b,p,r,s} + '-' + ≥10 [A-Za-z0-9-]
  regexRule("slack_token", `${WB_START}xox[abprs]-[A-Za-z0-9-]{10,}${WB}`, ""),

  // 13. slack_app_token — self-contained shape; WHOLE match replaced
  regexRule("slack_app_token", `${WB_START}xapp-\\d+-[A-Za-z0-9]+-\\d+-[a-f0-9]+${WB}`, ""),

  // 14. stripe_key — (r|s|t)k_(test|live)_ + ≥24 [0-9a-zA-Z]
  regexRule("stripe_key", `${WB_START}(?:r|s|t)k_(?:test|live)_[0-9a-zA-Z]{24,}${WB}`, ""),

  // 15. firebase_domain — 1–30 [a-z0-9-] + .firebaseapp.com
  regexRule("firebase_domain", `${WB_START}[a-z0-9-]{1,30}\\.firebaseapp\\.com`, ""),

  // 16. private_key_block — PEM BEGIN…END; linear cursor walk (pem.ts) so
  // adversarial inputs with many unterminated headers stay bounded-time.
  // Detection requires a COMPLETE block (an unterminated header survives and
  // must not be reported, so containsSensitive(redactString(t)) stays false,
  // A5.7).
  {
    id: "private_key_block",
    detect: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/,
    detectFn(text: string): boolean {
      return walkPrivateKeyBlocks(text).found;
    },
    apply(text: string): string {
      return walkPrivateKeyBlocks(text).text;
    },
  },

  // 17. jwt — eyJ + three dot-separated base64url segments (≥10/≥10/≥5)
  regexRule(
    "jwt",
    `${WB_START}eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}${WB}`,
    "",
  ),
];

// ---------------------------------------------------------------------------
// Rows 18–22 (case-insensitive context rules, A4.2)
// ---------------------------------------------------------------------------

/**
 * Row 18: bearer_authorization — header/assignment context REQUIRED.
 * Bare `Bearer <token>` without header context MUST NOT match at all
 * (benign: "the bearer of the ring"). Separator normalized to `: `,
 * quoting dropped, header name preserved.
 */
rules.push(
  regexRule(
    "bearer_authorization",
    "(proxy-authorization|x-api-key|authorization)\\s*[:=]\\s*\"?bearer\\s+" +
      `${TOKEN_CHARS}{6,}"?`,
    "i",
    (_match, p1) => `${p1 ?? "Authorization"}: [REDACTED:bearer_authorization]`,
  ),
);

/**
 * Row 19: assigned_secret — sensitive keyword + `[:=]` + value (quoted ≥4
 * chars, or bare ≥8 of the token class). Key name preserved, separator
 * normalized to `: `. Keyword set per N2 (includes `apikey`); hyphen and
 * underscore variants equivalent, case-insensitive.
 */
const ASSIGNED_SECRET_WORDS = [
  "access[-_]token", "refresh[-_]token", "client[-_]secret", "private[-_]key",
  "auth[-_]token", "api[-_]key", "api[-_]secret", "apikey", "credentials",
  "password", "passwd", "secret", "token", "pwd",
].join("|");

rules.push(
  regexRule(
    "assigned_secret",
    `\\b(${ASSIGNED_SECRET_WORDS})\\s*[:=]\\s*` +
      `(?:"${TOKEN_CHARS}{4,}"|'${TOKEN_CHARS}{4,}'|${TOKEN_CHARS}{8,})`,
    "i",
    (_match, p1) => `${p1 ?? "secret"}: [REDACTED:assigned_secret]`,
  ),
);

/**
 * Row 20: json_credential — quoted-JSON assignment shape; WHOLE match
 * replaced by `"<key>": [REDACTED:json_credential]` (key name and its
 * quotes preserved, value's quotes dropped, marker OUTSIDE any quoting) so
 * the rule cannot re-match its own output (A2.2, A3.6a). The value MUST NOT
 * contain marker text (OQ-5 terminality: a spoofed marker inside the value
 * survives verbatim and the shape is not consumed).
 */
const JSON_CRED_KEYS = [
  "api_key", "apiKey", "access_token", "accessToken", "refresh_token",
  "client_secret", "private_key", "credentials", "password", "secret",
].join("|");

rules.push(
  regexRule(
    "json_credential",
    `"(${JSON_CRED_KEYS})"\\s*:\\s*"` +
      `(?![^"\\n]*\\[REDACTED:)(?:\\\\.|[^"\\n])+"`,
    "i",
    (_match, p1) => `"${p1 ?? "secret"}": [REDACTED:json_credential]`,
  ),
);

/**
 * Row 21: url_password — `https?://` + `user:password@host` (COLON REQUIRED;
 * a bare `user@` URL survives). The URL extent is the userinfo@host PORTION
 * ONLY, terminating at the first `/`, `?`, `#`, or whitespace; scheme and
 * path/query survive. Marker text in the URL prefix disqualifies the match
 * (OQ-5 terminality).
 */
rules.push(
  regexRule(
    "url_password",
    "(https?)\\:\\/\\/" +
      "(?![^\\s/?#]*\\[REDACTED:)" +
      "[^\\s/?#]*:[^\\s/?#]*@[^\\s/?#]*",
    "i",
    (_match, p1) => `${p1 ?? "https"}://[REDACTED:url_password]`,
  ),
);

/**
 * Row 22: env_var_assignment — generalized: an uppercase env-var name
 * `[A-Z][A-Z0-9_]*` ending in a sensitive suffix + `=` + non-empty value
 * from the token class, which MUST exclude `[` so the emitted output
 * `NAME=[REDACTED:env_var_assignment]` cannot re-match (A3.6a). The
 * variable NAME is preserved. Case-insensitive per A4.2.
 */
const ENV_SUFFIXES = [
  "_ACCESS_TOKEN", "_REFRESH_TOKEN", "_CLIENT_SECRET", "_API_SECRET", "_API_KEY",
  "_PRIVATE_KEY", "_SECRET", "_PASSWORD", "_PASSWD", "_TOKEN",
].join("|");

rules.push(
  regexRule(
    "env_var_assignment",
    `(?<![A-Za-z0-9_])((?:[A-Za-z][A-Za-z0-9_]*)?(?:${ENV_SUFFIXES}))\\s*=\\s*${TOKEN_CHARS}+`,
    "i",
    (_match, p1) => `${p1 ?? "NAME"}=[REDACTED:env_var_assignment]`,
  ),
);

// ---------------------------------------------------------------------------
// Rows 23–24 (case-sensitive where irrelevant)
// ---------------------------------------------------------------------------

// 23. email — standard local@domain.tld shape; FULL address replaced.
rules.push(
  regexRule(
    "email",
    `(?<!/)(?<![A-Za-z0-9_])(?=[^\\s@]{1,64}@)[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]{1,63}\\.)+[A-Za-z]{2,63}${WB}`,
    "",
  ),
);

// 24. ssn — \d{3}-\d{2}-\d{4}, word-bounded.
rules.push(
  regexRule("ssn", `${WB_START}[0-9]{3}-[0-9]{2}-[0-9]{4}${WB}`, ""),
);

// ---------------------------------------------------------------------------
// Row 25 — credit_card: masking-only custom engine, never emits a marker.
// ---------------------------------------------------------------------------

export interface CardMaskResult {
  readonly text: string;
  readonly found: boolean;
}

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

/**
 * Row 25 masker (normative shape): 13–19 digits with optional single
 * separators (space/dash) between digit groups — at most ONE separator
 * between adjacent digits, NO leading or trailing separator, and each
 * separator-delimited digit group is 1–4 digits. Digit-count gate: <13 or
 * >19 digits ⇒ survive. ALL-ZERO placeholder (every digit `0`) ⇒ survive.
 * Otherwise mask IN PLACE: every digit → `•`, separators and length kept.
 * This rule NEVER emits a marker (A2.2); the masked output contains no
 * digits, so A5.7 stays valid.
 *
 * Candidate semantics (documented for review; regex-equivalent, linear-time):
 * a candidate starts only at a digit whose predecessor is not a digit
 * (digit-boundary anchor) and is the leftmost-longest valid shape:
 *  - an UNseparated digit run of 13–19 digits (a run longer than 19, or a
 *    starting run longer than 4 digits that cannot reach the gate, is not a
 *    card — no candidate may start inside a digit run); or
 *  - separator-delimited groups of 1–4 digits each, totalling 13–19 digits;
 *    a group longer than 4 digits ends the candidate before it. The full
 *    contiguous grouped candidate is counted before applying the 13–19 gate;
 *    candidates over 19 digits survive wholesale rather than being chunked.
 * The gate and the all-zero exception evaluate the WHOLE candidate. Rejected
 * candidates are retried from the next boundary-anchored digit, so the scan
 * is O(n) with a small constant — no catastrophic backtracking (A5.2a).
 */
export function applyCardMasking(text: string): string {
  let result = "";
  let cursor = 0;
  let found = false;
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isDigit(text[i] as string)) {
      i += 1;
      continue;
    }
    // Digit-boundary anchor: a candidate cannot start after another digit.
    if (i > 0 && isDigit(text[i - 1] as string)) {
      i += 1;
      continue;
    }
    const start = i;
    // First (unseparated) run from the anchor.
    let j = start;
    while (j < n && isDigit(text[j] as string)) {
      j += 1;
    }
    const firstRun = j - start;
    let end = -1; // match end when a candidate is accepted
    if (firstRun > 4) {
      // Unseparated alternative: the whole run is one token.
      if (firstRun >= 13 && firstRun <= 19 && !isAllZero(text, start, j)) {
        end = j;
      }
      // Whether masked or rejected, no candidate can start inside the run.
      if (end < 0) {
        i = j;
        continue;
      }
    } else {
      // Separated-groups alternative: groups of 1–4 digits, single seps,
      // total 13–19 digits; the cap or a long group ends the candidate.
      let total = firstRun;
      let allZero = isAllZero(text, start, j);
      let k = j;
      let candidateEnd = -1;
      for (;;) {
        // A separator continues the candidate only if single and followed
        // by a digit.
        if (k < n && (text[k] === " " || text[k] === "-") && k + 1 < n && isDigit(text[k + 1] as string)) {
          const groupStart = k + 1;
          let g = groupStart;
          while (g < n && isDigit(text[g] as string)) {
            g += 1;
          }
          const groupLen = g - groupStart;
          if (groupLen > 4) {
            break; // candidate ends before this separator
          }
          total += groupLen;
          if (allZero) {
            for (let x = groupStart; x < g; x += 1) {
              if ((text[x] as string) !== "0") {
                allZero = false;
                break;
              }
            }
          }
          k = g;
        } else {
          break;
        }
      }
      candidateEnd = k;
      if (total >= 13 && total <= 19 && !allZero) {
        end = candidateEnd;
      }
      // Resume after the consumed candidate extent (masked or rejected);
      // later groups in the same extent get their own anchored chances.
      i = candidateEnd > start ? candidateEnd : start + 1;
      if (end < 0) {
        continue;
      }
    }
    found = true;
    result += text.slice(cursor, start);
    for (let m = start; m < end; m += 1) {
      const c = text[m] as string;
      result += isDigit(c) ? "•" : c;
    }
    cursor = end;
    i = end;
  }
  if (!found) {
    return text;
  }
  result += text.slice(cursor);
  return result;
}

function isAllZero(text: string, from: number, to: number): boolean {
  for (let k = from; k < to; k += 1) {
    const c = text[k] as string;
    if (isDigit(c) && c !== "0") {
      return false;
    }
  }
  return true;
}

/** Detection-only view for the inspection API (A2.4). */
export function cardDetected(text: string): boolean {
  return applyCardMasking(text) !== text;
}

/** Rows 1–24 in normative application order. Row 25 (credit_card) is applied last by the pipeline. */
export const STRING_RULES: readonly StringRule[] = rules;
