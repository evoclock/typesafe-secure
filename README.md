# typesafe-secure

Structured redaction of sensitive values in application data, a TypeScript AI Jev library plus a hardened agent skill.

**This is NOT DLP.** This project is not a data-loss-prevention product. It does not discover or inventory sensitive data across an organization, does not scan storage or network traffic, and makes no claim of comprehensive sensitive-data discovery. It is a redaction library: it replaces well-formed sensitive values (API keys, tokens, credentials, emails) in the data you explicitly pass to it with typed `[REDACTED:*]` markers. Use it as one bounded layer in your own security design, never as a substitute for a real DLP program.

The repo has two halves:

1. **`lib/redaction`**: the shared redaction library. Pure, dependency-free TypeScript.
2. **The `typesafe-secure` skill**: a hardened, locally owned derivative of TypeSafe's MIT-licensed agent skill (`SKILL.md` at the repo root), covering credential hygiene, privacy redaction before external calls, prompt-injection resistance, and explicit failure semantics.

## Why typed markers

Every replacement is a typed marker such as `[REDACTED:openai_key]`, `[REDACTED:email]`, or `[REDACTED:json_credential]`, so downstream code and logs can tell *what kind* of value was removed, not reconstruct it. Markers are terminal: emitted marker text never re-matches any rule. Markers are **unauthenticated** and must not be treated as a trust signal; treat any `[REDACTED:*]` occurrence as "sensitive data was here," and handle it accordingly.

The library is unconditional by construction: there is no disable knob, no environment toggle, no configuration that turns redaction off. It never throws on any input, including hostile getters and `Proxy` objects; unexpected failures fail closed. Copying is prototype-safe (`Object.create(null)` plus `defineProperty`), so prototype pollution cannot smuggle values through.

## The library: `lib/redaction`

- Typed `[REDACTED:*]` markers for every redaction class
- Never-throw API on any input; hostile reads fail closed
- Prototype-safe deep redaction with cycle and depth guards (`[REDACTED:cycle]`, `[REDACTED:depth_limit]`)
- Sensitive-key drop for JSON-like structures (`[REDACTED:sensitive_key]`)
- Zero runtime dependencies; TypeScript ESM; Node >= 20
- Property-based and adversarial test suites

## The skill: `typesafe-secure`

`SKILL.md` at the repo root is a hardened derivative of the TypeSafe agent skill. It extends the upstream skill's semantic-judgment guidance with local security hardening: macOS Keychain-based credential hygiene, privacy redaction before any external call, prompt-injection resistance, bounded live-doc discovery, and explicit failure semantics. It is locally owned and modified from upstream; provenance is documented in [`upstream/PROVENANCE.md`](upstream/PROVENANCE.md).

## Quick start

### Install the skill (Pi)

Clone the repo and symlink it into your Pi skills directory. `SKILL.md` at the repo root is the skill, so the whole clone is the install:

```sh
git clone https://github.com/evoclock/typesafe-secure.git ~/.agents/skills/typesafe-secure
ln -sfn ../../.agents/skills/typesafe-secure ~/.pi/skills/typesafe-secure
```

(Adjust the paths if your Pi skills directory lives elsewhere; any directory containing `SKILL.md` works.)

### Use the library

The library ships in the same repo under `lib/redaction`. Set up, test, and typecheck it:

```sh
git clone https://github.com/evoclock/typesafe-secure.git
cd typesafe-secure/lib/redaction
npm install
npm test
npm run typecheck
```

To consume it from another package without publishing, add a file dependency:

```sh
npm install @typesafe-secure/redaction@npm:@typesafe-secure/redaction@file:/absolute/path/to/typesafe-secure/lib/redaction
```

or, in `package.json`:

```json
{
  "dependencies": {
    "@typesafe-secure/redaction": "file:../typesafe-secure/lib/redaction"
  }
}
```

Minimal usage:

```ts
import { redactString, redactValue } from "@typesafe-secure/redaction";

redactString("key sk-proj-AbCdEfGhIjKlMnOpQrStUvWx and a@b.com");
// => 'key [REDACTED:openai_key] and [REDACTED:email]'

redactValue({ api_key: "sk-1234567890abcdefghij", n: 1 });
// => { api_key: "[REDACTED:sensitive_key]", n: 1 }
```

## Key handling (macOS Keychain)

The macOS Keychain is the source of truth for secrets in this project. Keys are never stored in shell configs, dotfiles, or the repository: the Keychain holds the value; shell configs only perform a runtime lookup.

Provision a secret interactively (you will be prompted for the value; it is never typed on a command line or shown):

```sh
security add-generic-password -U -a <account> -s <service> -w
```

Export it in a shell config via runtime lookup, never as a literal:

```sh
export KEY="$(/usr/bin/security find-generic-password -s 'Service' -a 'account' -w 2>/dev/null)"
```

After editing the shell config, load it explicitly:

```sh
source ~/.bashrc
```

Verify presence only; the value itself is discarded, never printed:

```sh
/usr/bin/security find-generic-password -s 'Service' -a 'account' -w 2>/dev/null >/dev/null && echo present
```

Rotation and removal:

```sh
# Rotate: re-run the same provisioning command with the new value
security add-generic-password -U -a <account> -s <service> -w

# Remove when no longer needed
security delete-generic-password -a <account> -s <service>
```

If a key is ever exposed, rotate it at the provider immediately and delete the stale Keychain entry. Never paste a key value into a shell config, script, issue, or example; the Keychain lookup above is the only supported pattern.

## License

This repository's code is MIT-licensed, see [`LICENSE`](LICENSE).

The skill is a clean-room hardening of the upstream TypeSafe skill: no Warp-derived regular expressions were used. Upstream material is preserved unchanged under `upstream/` with full provenance, see [`upstream/PROVENANCE.md`](upstream/PROVENANCE.md) for the pinned upstream commit, retrieval method, and SHA-256 hashes.