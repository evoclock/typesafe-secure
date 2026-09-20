// SPDX-License-Identifier: MIT
// Traversal semantics: A5.2, A5.2a (adversarial classes), A5.3, A5.4, A5.5.
// All fixtures are synthetic (A3.5).
import { test } from "node:test";
import assert from "node:assert";
import { redactValue, redactString, SENSITIVE_KEYS } from "../src/index.js";

const KEY_MARK = "[REDACTED:sensitive_key]";
const DEPTH_MARK = "[REDACTED:depth_limit]";
const CYCLE_MARK = "[REDACTED:cycle]";
const OPAQUE_MARK = "[REDACTED:opaque]";
const OPENAI = "sk-" + "q".repeat(25);

function deepObject(levels: number): object {
  let v: unknown = { leaf: OPENAI };
  for (let i = 0; i < levels; i += 1) v = { inner: v };
  return v as object;
}

function deepArray(levels: number): unknown[] {
  let v: unknown = OPENAI;
  for (let i = 0; i < levels; i += 1) v = [v];
  return v as unknown[];
}

test("A5.2 nested/mixed trees, empty leaves, mixed-type arrays", () => {
  const input = {
    outer: {
      middle: [{ deep: { password: "anything-here" } }],
      note: OPENAI,
    },
    mixed: ["sk-" + "q".repeat(25), 7, null, { pwd: "abcdefghij" }, [true]],
    empty: {},
    emptyList: [],
    nil: null,
    maybe: undefined,
    n: 42,
    b: true,
  };
  const out = redactValue(input) as Record<string, any>;
  assert.equal(out.outer.middle[0].deep.password, KEY_MARK);
  assert.equal(out.outer.note, "[REDACTED:openai_key]");
  assert.equal(out.mixed[0], "[REDACTED:openai_key]");
  assert.equal(out.mixed[1], 7);
  assert.equal(out.mixed[2], null);
  assert.equal(out.mixed[3].pwd, KEY_MARK);
  assert.equal(out.mixed[4][0], true);
  assert.deepEqual(out.empty, {});
  assert.deepEqual(out.emptyList, []);
  assert.equal(out.nil, null);
  assert.equal("maybe" in out, true);
  assert.equal(out.maybe, undefined);
  assert.equal(out.n, 42);
  assert.equal(out.b, true);
});

test("A3.3a prototype-safe output: null prototype, own data keys, no pollution", () => {
  const input = JSON.parse(
    '{"__proto__":{"polluted":1},"constructor":"c","ok":"y"}',
  ) as Record<string, unknown>;
  const out = redactValue(input) as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(out), null);
  assert.deepEqual(Object.keys(out).sort(), ["__proto__", "constructor", "ok"]);
  const desc = Object.getOwnPropertyDescriptor(out, "__proto__");
  assert.ok(desc, "__proto__ must be an own data property");
  assert.equal(desc.writable, true);
  assert.deepEqual(desc.value, { polluted: 1 });
  assert.equal(({} as { polluted?: unknown }).polluted, undefined);
  assert.equal(Object.prototype.hasOwnProperty("polluted"), false);
});

test("A3.4/OQ-4 Map/Set/Date/RegExp/functions/symbols fail closed as opaque", () => {
  assert.equal(redactValue(new Set(["sk-" + "q".repeat(25)])), OPAQUE_MARK);
  const wrappedMap = redactValue({ m: new Map([["token", "abcdefghij"]]) }) as Record<string, unknown>;
  assert.equal(wrappedMap.m, OPAQUE_MARK);
  const wrappedDate = redactValue({ d: new Date(0) }) as Record<string, unknown>;
  assert.equal(wrappedDate.d, OPAQUE_MARK);
  const wrappedRe = redactValue({ r: /x/g }) as Record<string, unknown>;
  assert.equal(wrappedRe.r, OPAQUE_MARK);
  assert.equal(redactValue(() => 1), OPAQUE_MARK);
  assert.equal(redactValue(Symbol("s")), OPAQUE_MARK);
  const wrappedFn = redactValue({ f: () => 1 }) as Record<string, unknown>;
  assert.equal(wrappedFn.f, OPAQUE_MARK);
});

test("A3.4/OQ-4 class instances are traversed via own enumerable properties", () => {
  class Box {
    token = "abcdefghij";
    keep = "plain";
  }
  const out = redactValue(new Box()) as Record<string, unknown>;
  assert.equal(out.token, KEY_MARK);
  assert.equal(out.keep, "plain");
});

test("A3.4/A5.5 cycle guard terminates with [REDACTED:cycle]", () => {
  const a: Record<string, unknown> = { name: "root" };
  a.self = a;
  const out = redactValue(a) as Record<string, unknown>;
  assert.equal(out.name, "root");
  assert.equal(out.self, CYCLE_MARK);

  const arr: unknown[] = [1];
  arr.push(arr);
  const outArr = redactValue(arr) as unknown[];
  assert.equal(outArr[0], 1);
  assert.equal(outArr[1], CYCLE_MARK);

  // Re-shared (non-cyclic) references are re-traversed, not cycle-marked.
  const shared: Record<string, unknown> = { v: OPENAI };
  const two = { a: shared, b: shared };
  const outTwo = redactValue(two) as Record<string, Record<string, string>>;
  assert.equal(outTwo.a!.v, "[REDACTED:openai_key]");
  assert.equal(outTwo.b!.v, "[REDACTED:openai_key]");
});

test("A3.4/A5.5 exact MAX_DEPTH boundary: 32 replaced, 31 traversed, no throw", () => {
  const root = redactValue(deepObject(32)) as Record<string, unknown>;
  let v: unknown = root;
  for (let i = 1; i <= 30; i += 1) {
    assert.equal(typeof v, "object");
    v = (v as Record<string, unknown>).inner;
  }
  assert.deepEqual(v, { inner: { inner: DEPTH_MARK } });

  const arrRoot = redactValue(deepArray(32));
  let w: unknown = arrRoot;
  for (let i = 1; i <= 30; i += 1) w = (w as unknown[])[0];
  assert.deepEqual(w, [[DEPTH_MARK]]);

  // Depth 31 subtree itself survives and its string leaves are shape-redacted.
  const root31 = redactValue(deepObject(31)) as Record<string, any>;
  let u: Record<string, any> = root31;
  for (let i = 1; i <= 30; i += 1) u = u.inner;
  assert.equal(typeof u.inner.leaf, "string");
  assert.equal(u.inner.leaf.includes("q"), false);
});

test("A5.3 all-type sensitive-key drop, at every nesting level, every key form", () => {
  const mixedCase = (key: string): string =>
    [...key].map((char, index) => index % 2 === 0 ? char.toUpperCase() : char).join("");
  const keyForms = new Set<string>();
  for (const canonical of SENSITIVE_KEYS) {
    keyForms.add(canonical);
    keyForms.add(canonical.toUpperCase());
    keyForms.add(mixedCase(canonical));
    if (canonical.includes("_")) {
      const hyphenated = canonical.replaceAll("_", "-");
      keyForms.add(hyphenated);
      keyForms.add(hyphenated.toUpperCase());
      keyForms.add(mixedCase(hyphenated));
    }
  }
  const values: unknown[] = [
    "abcdefghij",
    12345,
    false,
    null,
    { nested: { deeper: "x" } },
    [1, "two", { three: 3 }],
  ];
  for (const key of keyForms) {
    for (const value of values) {
      const input: Record<string, unknown> = {};
      input[key] = value;
      const out = redactValue(input) as Record<string, unknown>;
      assert.equal(
        out[key],
        KEY_MARK,
        `key=${key} value=${JSON.stringify(value)}`,
      );
    }
  }
  const deep = redactValue({ a: { b: { c: { credentials: { x: 1 } } } } }) as Record<string, any>;
  assert.equal(deep.a.b.c.credentials, KEY_MARK);
  // Non-sensitive keys with lookalike names survive the key rule (A2.6).
  const benign = redactValue({ tokenizer: "enabled", passwordHint: "x", userPassword: { a: 1 } }) as Record<string, any>;
  assert.equal(benign.tokenizer, "enabled");
  assert.equal(benign.passwordHint, "x");
  assert.equal(benign.userPassword.a, 1);
});

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value as object)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}

test("A5.4 no input mutation; deep-frozen inputs never throw", () => {
  const original = {
    list: [{ password: "abcdefghij" }, OPENAI],
    nested: { token: { deep: true } },
  };
  const snapshot = JSON.stringify(original);
  const frozen = deepFreeze(JSON.parse(snapshot));
  assert.doesNotThrow(() => redactValue(frozen));
  assert.equal(JSON.stringify(frozen), snapshot);

  const out = redactValue(original) as Record<string, any>;
  assert.equal(JSON.stringify(original), snapshot);
  assert.equal((out.list[0] as { password: string }).password, KEY_MARK);
  assert.equal((original.list[0] as { password: string }).password, "abcdefghij");
  assert.equal((out.list[1] as string).includes("q"), false);
  // Sensitive positions are replaced, not shared-and-mutated.
  assert.notEqual(out.nested, original.nested);
});

test("A5.2a hostile array indices fail closed per element", () => {
  const hostile = [1, 2, 3];
  Object.defineProperty(hostile, "1", {
    enumerable: true,
    get() {
      throw new Error("nope");
    },
  });
  assert.deepEqual(redactValue(hostile), [1, OPAQUE_MARK, 3]);

  const nested = redactValue({ values: hostile }) as Record<string, unknown>;
  assert.deepEqual(nested.values, [1, OPAQUE_MARK, 3]);

  const proxied = new Proxy([1, 2, 3], {
    get(target, key, receiver) {
      if (key === "1") throw new Error("trap");
      return Reflect.get(target, key, receiver);
    },
  });
  assert.deepEqual(redactValue(proxied), [1, OPAQUE_MARK, 3]);
});

test("A5.2a hostile getters and throwing Proxies fail closed, never throw", () => {
  const hostile: Record<string, unknown> = { ok: "plain" };
  Object.defineProperty(hostile, "boom", {
    enumerable: true,
    get() {
      throw new Error("nope");
    },
  });
  const out = redactValue(hostile) as Record<string, unknown>;
  assert.equal(out.ok, "plain");
  assert.equal(out.boom, OPAQUE_MARK);

  const getTrap = new Proxy(
    { a: 1 },
    {
      get() {
        throw new Error("trap");
      },
    },
  );
  const wrapped = redactValue({ safe: 1, hostile: getTrap }) as Record<string, unknown>;
  assert.equal(wrapped.safe, 1);
  assert.equal(Object.getPrototypeOf(wrapped.hostile), null);
  assert.equal((wrapped.hostile as Record<string, unknown>).a, OPAQUE_MARK);

  const keysTrap = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error("trap");
      },
    },
  );
  assert.equal(redactValue(keysTrap), OPAQUE_MARK);

  const benignProxy = redactValue(new Proxy({ keep: "plain" }, {})) as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(benignProxy), null);
  assert.equal(benignProxy.keep, "plain");

  assert.equal(typeof redactString("plain"), "string");
});
