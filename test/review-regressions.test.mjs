import test from "node:test";
import assert from "node:assert/strict";
import { createWorker } from "../src/index.js";

const okValidator = (regex) => ({ valid: true, byteLength: regex.length, rust: { valid: true, diagnostic: null }, cloudflare: { valid: true, diagnostics: [] } });
async function sourceAndResponse() {
  const response = await createWorker(okValidator).fetch(new Request("https://example.invalid/"));
  return { response, html: await response.text() };
}

test("page applies a restrictive CSP and describes card fixtures accurately", async () => {
  const { response, html } = await sourceAndResponse();
  assert.match(response.headers.get("content-security-policy") || "", /default-src 'none'/);
  assert.match(response.headers.get("content-security-policy") || "", /script-src 'nonce-/);
  assert.match(html, /synthetic PAN-shaped detector fixtures using test BINs/i);
  assert.doesNotMatch(html, /documented payment-network test BINs/i);
});

test("client source preserves copy labels and hands SSNs to an SSN regex", async () => {
  const { html } = await sourceAndResponse();
  assert.match(html, /const originalText=b\.textContent/);
  assert.match(html, /setTimeout\(\(\)=>b\.textContent=originalText,1200\)/);
  assert.match(html, /SSN_REGEX/);
  assert.match(html, /000-/);
});

test("key client validates DER prefixes and handles generation errors", async () => {
  const { html } = await sourceAndResponse();
  assert.match(html, /assertDerPrefix/);
  assert.match(html, /catch\(error\)/);
  assert.match(html, /Unable to generate key pair/);
  assert.match(html, /aria-live="assertive"/);
});

test("private key source excludes persistent, logging, network and URL sinks", async () => {
  const { html } = await sourceAndResponse();
  for (const forbidden of ["localStorage", "sessionStorage", "indexedDB", "caches.open", "console.log", "history.pushState", "URLSearchParams"]) {
    assert.doesNotMatch(html, new RegExp(forbidden.replace(".", "\\.")));
  }
  assert.doesNotMatch(html, /fetch\([^)]*inMemoryPrivateKey/);
});
