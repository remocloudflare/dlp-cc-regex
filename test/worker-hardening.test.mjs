import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createWorker, PRESETS } from "../src/index.js";

const okValidator = (regex) => ({
  valid: true,
  byteLength: Buffer.byteLength(regex, "utf8"),
  rust: { valid: true, diagnostic: null },
  cloudflare: { valid: true, diagnostics: [] },
});
const worker = createWorker(okValidator);
const jsonRequest = (path, value, init = {}) => new Request(`https://example.invalid${path}`, {
  method: "POST",
  headers: { "content-type": "application/json", ...(init.headers || {}) },
  body: typeof value === "string" ? value : JSON.stringify(value),
});

async function rootHtml() {
  return (await worker.fetch(new Request("https://example.invalid/"))).text();
}

test("UI groups presets by category, keeps custom, shows selected preset note, and has no flags control", async () => {
  const body = await rootHtml();
  for (const category of new Set(PRESETS.map(({ category }) => category))) {
    assert.match(body, new RegExp(`<optgroup\\s+label=["']${category.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`));
  }
  assert.match(body, /<option[^>]+value=["']custom["']/);
  assert.match(body, /id=["']preset-note["']/);
  assert.doesNotMatch(body, /id=["']flags["']/);
  assert.match(body, /preset-note["']\)\.textContent\s*=\s*p\.note/);
});

test("root uses the shared penguin background with readable layered overlays", async () => {
  const body = await rootHtml();
  assert.match(body, /url\(["']https:\/\/itlinux\.cc\/assets\/bg\.webp\?v=5["']\)/);
  assert.match(body, /body::before\s*\{[^}]*position:\s*fixed[^}]*z-index:\s*-2[^}]*background-size:\s*cover[^}]*background-position:\s*center top[^}]*filter:\s*saturate\(\.95\) brightness\(\.72\)/s);
  assert.match(body, /body::after\s*\{[^}]*position:\s*fixed[^}]*z-index:\s*-1[^}]*linear-gradient/s);
  assert.match(body, /body\s*\{[^}]*min-height:\s*100vh[^}]*isolation:\s*isolate/s);
});

test("root includes a compact Who am I bio and linked attribution", async () => {
  const body = await rootHtml();
  const text = body.replace(/<[^>]+>/g, " ").replace(/\s+\./g, ".").replace(/\s+/g, " ");
  assert.match(body, /<h2>Who am I<\/h2>/);
  assert.match(text, /I'm Remo Mattei\. I build practical Cloudflare One, Zero Trust, Workers, and Linux demos at itlinux\.cc\./);
  assert.match(text, /Built by Remo Mattei · Powered by Cloudflare One/);
  assert.match(body, /<a href="https:\/\/itlinux\.cc\/">Remo Mattei<\/a>/);
  assert.match(body, /<a href="https:\/\/itlinux\.cc\/">itlinux\.cc<\/a>/);
  assert.match(body, /<a href="https:\/\/whoami\.itlinux\.cc\/">Who Am I demo<\/a>/);
  assert.match(body, /<a href="https:\/\/www\.cloudflare\.com\/zero-trust\/products\/">Cloudflare One<\/a>/);
});

test("client ignores stale scan responses after preset changes", async () => {
  const body = await rootHtml();
  assert.match(body, /const scanSerial = \+\+scanGeneration/);
  assert.match(body, /if \(scanSerial !== scanGeneration\) return;/);
  assert.match(body, /scanController\?\.abort\(\)/);
});

test("inline scripts parse and every literal getElementById reference exists", async () => {
  const body = await rootHtml();
  const ids = new Set([...body.matchAll(/\sid=["']([^"']+)["']/g)].map((m) => m[1]));
  for (const match of body.matchAll(/\sdata-target=["']([^"']+)["']/g)) {
    assert.ok(ids.has(match[1]), `missing data-target element id ${match[1]}`);
  }
  const scripts = [...body.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  assert.ok(scripts.length > 0);
  const dir = mkdtempSync(join(tmpdir(), "dlp-inline-"));
  try {
    scripts.forEach((script, index) => {
      const file = join(dir, `inline-${index}.js`);
      writeFileSync(file, script);
      const checked = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
      assert.equal(checked.status, 0, checked.stderr);
      for (const match of script.matchAll(/getElementById\(["']([^"']+)["']\)/g)) {
        assert.ok(ids.has(match[1]), `missing element id ${match[1]}`);
      }
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("POST /scan requires a bounded JSON object", async () => {
  const cases = [
    [new Request("https://example.invalid/scan", { method: "POST" }), 415],
    [new Request("https://example.invalid/scan", { method: "POST", headers: { "content-type": "application/json" } }), 400],
    [new Request("https://example.invalid/scan", { method: "POST", headers: { "content-type": "text/plain" }, body: "{}" }), 415],
    [jsonRequest("/scan", "{"), 400],
    [jsonRequest("/scan", "null"), 400],
    [jsonRequest("/scan", "[]"), 400],
    [jsonRequest("/scan", "\"x\""), 400],
  ];
  for (const [request, status] of cases) {
    const response = await worker.fetch(request);
    assert.equal(response.status, status);
    assert.equal(typeof (await response.json()).error, "string");
  }
});

test("POST /scan rejects invalid UTF-8 without replacement decoding", async () => {
  const request = new Request("https://example.invalid/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: new Uint8Array([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x3a, 0x31, 0x7d]),
  });
  const response = await worker.fetch(request);
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /UTF-8/);
});

test("POST /scan rejects declared and actual bodies over 128 KiB", async () => {
  const declared = jsonRequest("/scan", {}, { headers: { "content-length": String(128 * 1024 + 1) } });
  assert.equal((await worker.fetch(declared)).status, 413);
  const actual = jsonRequest("/scan", { text: "π".repeat(70_000), regex: "x" });
  assert.equal((await worker.fetch(actual)).status, 413);
});

test("chunked bodies stop pulling and cancel immediately after 128 KiB", async () => {
  const chunk = new Uint8Array(16 * 1024).fill(0x20);
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(chunk);
      if (pulls === 64) controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://example.invalid/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    duplex: "half",
  });

  const response = await worker.fetch(request);

  assert.equal(response.status, 413);
  assert.equal(cancelled, true);
  assert.ok(pulls <= 10, `expected near-threshold stop, pulled ${pulls} chunks`);
});

test("oversized regex is rejected before Rust validation", async () => {
  const throwingWorker = createWorker(() => { throw new Error("Rust must not run"); });
  const response = await throwingWorker.fetch(jsonRequest("/scan", { regex: "π".repeat(513), text: "" }));
  assert.equal(response.status, 413);
  assert.match((await response.json()).error, /1,024 UTF-8 bytes/i);
});

test("field limits, validation enum, and flags fail closed", async () => {
  const cases = [
    [{ regex: "x", text: "x".repeat(64 * 1024 + 1) }, 413],
    [{ regex: "x", text: "", name: "n".repeat(257) }, 400],
    [{ regex: "x", text: "", validation: "mod10" }, 400],
    [{ regex: "x", text: "", flags: "gi" }, 400],
  ];
  for (const [payload, status] of cases) {
    const response = await worker.fetch(jsonRequest("/scan", payload));
    assert.equal(response.status, status, JSON.stringify(payload).slice(0, 80));
    const body = await response.json();
    assert.equal(typeof body.error, "string");
    assert.equal(body.tf, undefined);
  }
});

test("invalid validation is rejected before Rust validation", async () => {
  const throwingWorker = createWorker(() => { throw new Error("Rust must not run"); });
  const response = await throwingWorker.fetch(jsonRequest("/scan", { regex: "x", validation: "bogus" }));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).tf, undefined);
});

test("explicit object may use empty regex without throwing", async () => {
  const response = await worker.fetch(jsonRequest("/scan", {}));
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).matches, []);
});

test("route method contract returns 404 or 405 with Allow", async () => {
  const cases = [
    ["/", "POST", 405, "GET"], ["/health", "POST", 405, "GET"],
    ["/api", "POST", 405, "GET"], ["/scan", "GET", 405, "POST"],
    ["/missing", "GET", 404, null],
  ];
  for (const [path, method, status, allow] of cases) {
    const response = await worker.fetch(new Request(`https://example.invalid${path}`, { method }));
    assert.equal(response.status, status);
    assert.equal(response.headers.get("allow"), allow);
  }
});

test("GET /api enforces enums and query field byte limits", async () => {
  assert.equal((await worker.fetch(new Request("https://example.invalid/api?regex=x&flags=gi"))).status, 400);
  assert.equal((await worker.fetch(new Request("https://example.invalid/api?regex=x&validation=bogus"))).status, 400);
  assert.equal((await worker.fetch(new Request(`https://example.invalid/api?regex=${"x".repeat(1025)}`))).status, 413);
});
