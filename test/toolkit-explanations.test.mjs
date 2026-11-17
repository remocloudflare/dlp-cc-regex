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

test("payload logging keys separate the numbered workflow, public output, and CLI fallback", async () => {
  const html = await page();
  const panel = html.match(/<section id="panel-keys"[\s\S]*?<\/section>\s*<\/main>/)?.[0];
  assert.ok(panel, "payload logging keys panel should exist");
  assert.match(panel, /class="toolkit-panel key-panel"/);
  assert.match(panel, /class="key-cards"/);
  for (const step of [
    "1 · Generate locally",
    "2 · Private key downloads automatically",
    "3 · Store it securely",
    "4 · Copy the public key into Cloudflare payload logging",
    "5 · Download again only in this page session",
  ]) assert.match(panel, new RegExp(step.replace("·", "\\·"), "i"));

  const workflow = panel.match(/<section class="card key-workflow">[\s\S]*?<\/section>/)?.[0];
  assert.ok(workflow);
  assert.match(workflow, /id="generate-key"[\s\S]*id="download-key-again"/);
  assert.doesNotMatch(workflow, /id="key-status"/);

  const output = panel.match(/<section class="card key-output">[\s\S]*?<\/section>/)?.[0];
  assert.ok(output);
  assert.match(output, /<h2>Public key output<\/h2>/);
  assert.match(output, /id="public-key"/);
  assert.match(output, />Copy public key<\/button>/);
  assert.match(output, /id="key-status"/);
  assert.doesNotMatch(output, /matched-data-cli|documentation|cannot recover/i);

  const fallback = panel.match(/<aside class="key-fallback"[\s\S]*?<\/aside>/)?.[0];
  assert.ok(fallback);
  assert.match(fallback, /\.\/matched-data-cli generate-key-pair/);
  assert.match(fallback, /Cloudflare key-generation documentation/);
  assert.equal((panel.match(/Cloudflare cannot recover it/gi) || []).length, 1);
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
