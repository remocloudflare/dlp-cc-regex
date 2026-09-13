import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  createDlpRegexValidator,
  instantiateRegexValidator,
} from "../src/regex-validator.js";
import { createWorker, PRESETS } from "../src/index.js";

const wasmPath = new URL("../src/regex_validator.wasm", import.meta.url);
let validateDlpRegex;

test.before(async () => {
  const bytes = await readFile(wasmPath);
  const rustValidator = await instantiateRegexValidator(bytes);
  validateDlpRegex = createDlpRegexValidator(rustValidator);
});

const rustCases = [
  [String.raw`\b\d(?:[ -]?\d){12,18}\b`, true, null],
  ["[", false, "unclosed character class"],
  [String.raw`(a)\1`, false, "backreferences are not supported"],
  ["foo(?=bar)", false, "look-around"],
  ["(?i:foo)", true, null],
  [String.raw`\p{Greek}{1,10}`, true, null],
];

for (const [pattern, expectedValid, diagnosticFragment] of rustCases) {
  test(`Rust regex validation: ${JSON.stringify(pattern)}`, () => {
    const result = validateDlpRegex(pattern);
    assert.equal(result.rust.valid, expectedValid);
    assert.equal(result.valid, expectedValid);
    if (diagnosticFragment) {
      assert.match(result.rust.diagnostic, new RegExp(diagnosticFragment, "i"));
    } else {
      assert.equal(result.rust.diagnostic, null);
    }
  });
}

test("Cloudflare DLP rejects regex source over 1,024 UTF-8 bytes", () => {
  const pattern = "π".repeat(513);
  const result = validateDlpRegex(pattern);
  assert.equal(result.byteLength, 1026);
  assert.equal(result.rust.valid, true);
  assert.equal(result.cloudflare.valid, false);
  assert.match(result.cloudflare.diagnostics.join(" "), /1,024 UTF-8 bytes/i);
  assert.equal(result.valid, false);
});

test("Cloudflare DLP rejects unbounded plus and star quantifiers", () => {
  for (const pattern of ["a+", "a*"]) {
    const result = validateDlpRegex(pattern);
    assert.equal(result.rust.valid, true, pattern);
    assert.equal(result.cloudflare.valid, false, pattern);
    assert.match(result.cloudflare.diagnostics.join(" "), /unbounded/i);
  }
});

test("Cloudflare DLP does not mistake escaped or class plus/star for quantifiers", () => {
  for (const pattern of [String.raw`a\+b\*`, String.raw`[+*]{1,3}`]) {
    const result = validateDlpRegex(pattern);
    assert.equal(result.valid, true, pattern);
    assert.deepEqual(result.cloudflare.diagnostics, [], pattern);
  }
});

test("every production preset passes authoritative Rust and Cloudflare validation", () => {
  for (const preset of PRESETS.filter(({ id }) => id !== "custom")) {
    const result = validateDlpRegex(preset.regex);
    assert.equal(
      result.valid,
      true,
      `${preset.id}: ${result.rust.diagnostic || result.cloudflare.diagnostics.join("; ")}`,
    );
  }
});

test("/scan reports authoritative validation for any supplied regex", async () => {
  const worker = createWorker(validateDlpRegex);
  const request = new Request("https://example.invalid/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "foo", regex: "foo(?=bar)", flags: "g" }),
  });
  const response = await worker.fetch(request);
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.regexValidation.rust.valid, false);
  assert.match(body.regexValidation.rust.diagnostic, /look-around/i);
  assert.equal(body.matches, undefined);
});

test("Rust scan returns authoritative matches and UTF-8/UTF-16 offsets", () => {
  const result = validateDlpRegex.scan("(a|aa){1,35}b", "π xx aab yy aaab", 500);

  assert.deepEqual(result, {
    matches: [
      { match: "aab", index: 5, length: 3, byteStart: 6, byteEnd: 9 },
      { match: "aaab", index: 12, length: 4, byteStart: 13, byteEnd: 17 },
    ],
    truncated: false,
  });
});

test("adversarial ambiguous alternation completes quickly in Rust", () => {
  const text = "a".repeat(60_000);
  const started = performance.now();
  const result = validateDlpRegex.scan("(a|aa){1,35}b", text, 500);
  const elapsedMs = performance.now() - started;

  assert.deepEqual(result.matches, []);
  assert.equal(result.truncated, false);
  assert.ok(elapsedMs < 1_000, `Rust scan took ${elapsedMs.toFixed(1)}ms`);
});

test("/scan returns authoritative Rust matching", async () => {
  const worker = createWorker(validateDlpRegex);
  const request = new Request("https://example.invalid/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "FOO foo", regex: "(?i:foo)", flags: "g" }),
  });
  const response = await worker.fetch(request);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.regexValidation.valid, true);
  assert.equal(body.preview, undefined);
  assert.equal(body.engine, "Rust regex 1.13.1 (authoritative)");
  assert.deepEqual(body.matches.map(({ match, index }) => ({ match, index })), [
    { match: "FOO", index: 0 },
    { match: "foo", index: 4 },
  ]);
});
