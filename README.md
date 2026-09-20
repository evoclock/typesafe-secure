# typesafe-secure

<p align="center">
  <img src="assets/Yamagane-origami.png" alt="typesafe-secure, Yamagane origami mark" width="140"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat" alt="License: MIT"/></a>
  <a href="https://www.npmjs.com/package/@evoclock/pi-typesafe-secure"><img src="https://img.shields.io/npm/v/@evoclock/pi-typesafe-secure?style=flat&label=pi-typesafe-secure" alt="npm version of pi-typesafe-secure"/></a>
  <a href="https://www.npmjs.com/package/@evoclock/redaction"><img src="https://img.shields.io/npm/v/@evoclock/redaction?style=flat&label=redaction" alt="npm version of redaction"/></a>
  <img src="https://img.shields.io/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white" alt="TypeScript"/>
</p>

One repository, **two npm packages**. This README covers both; they version independently.

- **`@evoclock/pi-typesafe-secure`** — the Pi package: a hardened `typesafe-ai` skill plus a redaction library, in one install.
- **`@evoclock/redaction`** — the redaction library on its own, for any Node >= 20 project.

If you came from npm: the title above is the **repository** name. It is deliberately version-free — check the badge row for each package's current version. A version in the title would describe only one of the two things published here, so the README pins none.

**This is NOT DLP.** This project is not a data-loss-prevention product. It does not discover or inventory sensitive data across an organization, does not scan storage or network traffic, and makes no claim of comprehensive sensitive-data discovery. It is a redaction library: it replaces well-formed sensitive values (API keys, tokens, credentials, emails) in the data you explicitly pass to it with typed `[REDACTED:*]` markers. Use it as one bounded layer in your own security design, never as a substitute for a real DLP program.

## What's inside

The two packages and their versioning:

| Package | Version | What it is |
|---|---|---|
| `@evoclock/pi-typesafe-secure` | [![npm](https://img.shields.io/npm/v/@evoclock/pi-typesafe-secure?style=flat&label=version)](https://www.npmjs.com/package/@evoclock/pi-typesafe-secure) | The Pi package: the hardened skill plus a bundled copy of the library. Bumps for any change to the skill, the docs, or the bundled library. |
| `@evoclock/redaction` | [![npm](https://img.shields.io/npm/v/@evoclock/redaction?style=flat&label=version)](https://www.npmjs.com/package/@evoclock/redaction) | The redaction library itself. Pure, dependency-free TypeScript. Its version only moves when the library code changes — doc-only releases of the outer package leave it untouched. |

If the two versions look out of step, that is the intended versioning, not staleness. The library's version only moves when library code changes; doc-only releases bump the Pi package alone. Install `@evoclock/redaction` to track the library version; install `@evoclock/pi-typesafe-secure` to get the library version the package was built with.

1. **The `typesafe-secure` skill** (`skills/typesafe-secure/SKILL.md`): a hardened, locally owned derivative of TypeSafe's MIT-licensed agent skill, covering credential hygiene, privacy redaction before external calls, prompt-injection resistance, and explicit failure semantics.
2. **`lib/redaction`**: the shared redaction library (the `@evoclock/redaction` package above), bundled into this package by its `files` manifest.

## Install (Pi)

From npm:

```sh
pi install npm:@evoclock/pi-typesafe-secure
```

Or from Git at a pinned tag (check the tags for the current release):

```sh
pi install git:github.com/evoclock/typesafe-secure@v0.1.2
```

Pi pins the ref and reconciles it on `pi update --extensions`.

## Other agents and harnesses

The library is a plain npm package and works in any Node >= 20 project:

```sh
npm install @evoclock/redaction
```

The skill is a single Markdown file. To use it with any agent harness that reads `SKILL.md`-style instruction files, install the npm package and point your agent at the shipped skill file:

```sh
skills/typesafe-secure/SKILL.md
```

Install location varies by harness; consult your harness's documentation for where skill files belong.

## Use the library

Standalone, from npm:

```sh
npm install @evoclock/redaction
```

The library ships as TypeScript source and is imported through its package root (`@evoclock/redaction`); deep imports like `@evoclock/redaction/src/...` are not supported API. Run it with a TypeScript-aware loader (tsx, ts-node, a bundler, or Node.js type stripping) or compile it with your own build.

Minimal usage:

```ts
import { redactString, redactValue } from "@evoclock/redaction";

redactString("key sk-proj-AbCdEfGhIjKlMnOpQrStUvWx and a@b.com");
// => 'key [REDACTED:openai_key] and [REDACTED:email]'

redactValue({ api_key: "sk-1234567890abcdefghij", n: 1 });
// => { api_key: "[REDACTED:sensitive_key]", n: 1 }
```

## Why typed markers

Every replacement is a typed marker such as `[REDACTED:openai_key]`, `[REDACTED:email]`, or `[REDACTED:json_credential]`, so downstream code and logs can tell *what kind* of value was removed, not reconstruct it. Markers are terminal: emitted marker text never re-matches any rule. Markers are **unauthenticated** and must not be treated as a trust signal; treat any `[REDACTED:*]` occurrence as "sensitive data was here," and handle it accordingly.

The library is unconditional by construction: there is no disable knob, no environment toggle, no configuration that turns redaction off. It never throws on any input, including hostile getters and `Proxy` objects; unexpected failures fail closed. Copying is prototype-safe (`Object.create(null)` plus `defineProperty`), so prototype pollution cannot smuggle values through.

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

## Maintenance: upstream re-sync

The skill is a pinned snapshot of the upstream TypeSafe skill. Upstream changes never alter this repo automatically; staying current is a deliberate ritual:

1. Fetch the upstream repo and diff `65a39f39..HEAD` on their side.
2. Review what changed; port anything relevant into the local derivative as an owner-approved, reviewed change.
3. Update `upstream/PROVENANCE.md` pins (commit and SHA-256) only when upstream material is actually re-copied.
4. Publish the new ref and update pinned installs.

## License

This repository's code is MIT-licensed, see [`LICENSE`](LICENSE).

The skill is a clean-room hardening of the upstream TypeSafe skill: no Warp-derived regular expressions were used. Upstream material is preserved unchanged under `upstream/` with full provenance, see [`upstream/PROVENANCE.md`](upstream/PROVENANCE.md) for the pinned upstream commit, retrieval method, and SHA-256 hashes.