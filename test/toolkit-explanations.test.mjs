import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createWorker } from "../src/index.js";

const okValidator = (regex) => ({ valid: true, byteLength: regex.length, rust: { valid: true, diagnostic: null }, cloudflare: { valid: true, diagnostics: [] } });

async function page() {
  return (await createWorker(okValidator).fetch(new Request("https://example.invalid/"))).text();
}

test("page presents the site-level toolkit identity and compact overview", async () => {
  const html = await page();
  assert.match(html, /<title>Regex Builder \| DLP Demo Toolkit<\/title>/);
  assert.match(html, /DLP Demo Toolkit/);
  assert.match(html, /What this toolkit does/);
  assert.match(html, /Build and validate Rust-compatible DLP regexes/);
  assert.match(html, /generate safe synthetic detector fixtures/i);
  assert.match(html, /create browser-local X25519 payload logging keys/i);
});

test("tabs define meaningful headers, descriptions, and document titles", async () => {
  const html = await page();
  for (const expected of [
    "Regex Builder | DLP Demo Toolkit",
    "Synthetic Demo Data | DLP Demo Toolkit",
    "Payload Logging Keys | DLP Demo Toolkit",
    "Author and test a Cloudflare DLP custom entry",
    "Generate safe, synthetic values for DLP demonstrations",
    "Generate X25519 keys for Cloudflare payload logging",
  ]) assert.match(html, new RegExp(expected.replace(/[|]/g, "\\|")));
  assert.match(html, /document\.title=tool\.title/);
  assert.match(html, /toolkit-title/);
  assert.match(html, /toolkit-intro/);
});

test("tool explanations describe safe handoff and key handling", async () => {
  const html = await page();
  assert.match(html, /Test in Regex Builder/);
  assert.match(html, /synthetic/i);
  assert.match(html, /public key/i);
  assert.match(html, /private key downloads automatically/i);
  assert.match(html, /retained only in page memory/i);
});

test("README documents all three tools, workflow, safety, and production URL", async () => {
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  for (const expected of [
    "DLP Demo Toolkit",
    "Regex Builder",
    "Synthetic Demo Data",
    "Payload Logging Keys",
    "Test in Regex Builder",
    "X25519",
    "private key",
    "https://dlp-regex.itlinux.cc/",
  ]) assert.match(readme, new RegExp(expected, "i"));
  assert.match(readme, /Never paste real customer data or credentials/i);
});
