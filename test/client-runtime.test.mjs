import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

import { createWorker } from "../src/index.js";

const okValidator = (regex) => ({ valid: true, byteLength: regex.length, rust: { valid: true, diagnostic: null }, cloudflare: { valid: true, diagnostics: [] } });

async function clientScript() {
  const html = await (await createWorker(okValidator).fetch(new Request("https://example.invalid/"))).text();
  return [...html.matchAll(/<script(?: nonce="[^"]+")?>([\s\S]*?)<\/script>/g)][0][1];
}

function element(id) {
  return { id, value: "", textContent: "", innerHTML: "", hidden: false, disabled: false, style: {}, dataset: {}, attributes: {}, children: [],
    setAttribute(name, value) { this.attributes[name] = value; },
    getAttribute(name) { return this.attributes[name]; },
    addEventListener() {}, appendChild(child) { this.children.push(child); }, append(...children) { this.children.push(...children); }, replaceChildren() { this.children = []; }, focus() {}, click() {},
  };
}

test("key generation downloads once, exposes only public key, and re-downloads identical private file", async () => {
  const ids = ["preset","regex","validation","in","name","preset-note","th-v","rows","rx","count","validation-status","compatibility-warn","toolkit-title","toolkit-intro","demo-type","demo-quantity","demo-format","generate-demo","demo-output","demo-status","copy-all-demo","test-demo","generate-key","download-key-again","public-key","key-status","tab-regex","panel-regex","tab-synthetic","panel-synthetic","tab-keys","panel-keys"];
  const elements = Object.fromEntries(ids.map((id) => [id, element(id)]));
  elements["demo-type"].value = "card"; elements["demo-quantity"].value = "10"; elements["demo-format"].value = "plain";
  for (const id of ["regex","validation","in","name"]) elements[id].addEventListener = () => {};
  const tabs = ["regex","synthetic","keys"].map((name) => { const tab = elements[`tab-${name}`]; tab.attributes["aria-controls"] = `panel-${name}`; return tab; });
  const copies = [{ dataset: { target: "public-key" }, textContent: "Copy public key" }];
  const downloads = [];
  const blobs = new Map(); let nextUrl = 0;
  const context = {
    crypto, Uint8Array, Blob, Date, String, Number, Array, Object, JSON, Math, setTimeout: (fn) => fn(), AbortController,
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    fetch: async () => ({ json: async () => ({ matches: [], regexValidation: okValidator("") }) }),
    navigator: { clipboard: { writeText() {} } },
    URL: { createObjectURL(blob) { const url = `blob:${++nextUrl}`; blobs.set(url, blob); return url; }, revokeObjectURL() {} },
    document: {
      title: "",
      getElementById(id) { return elements[id]; },
      querySelectorAll(selector) { return selector === '[role="tab"]' ? tabs : selector === 'button.copy[data-target]' ? copies : []; },
      createElement(tag) { const node = element(tag); node.click = () => { if (tag === "a") downloads.push({ filename: node.download, url: node.href }); }; return node; },
    },
    addEventListener() {},
  };
  vm.runInNewContext(await clientScript(), context);

  const cards = vm.runInNewContext("browserGenerateDemoData('card',100,'mixed')", context);
  const ssns = vm.runInNewContext("browserGenerateDemoData('ssn',100,'plain')", context);
  assert.equal(cards.length, 100);
  assert.ok(cards.every((value) => /^\d{4} \d{4}-\d{4} \d{4}$/.test(value)));
  assert.ok(ssns.every((value) => /^000-\d{2}-\d{4}$/.test(value)));

  await elements["generate-key"].onclick();

  assert.equal(downloads.length, 1);
  assert.match(downloads[0].filename, /^cloudflare-payload-logging-private-key-\d{8}-\d{6}\.txt$/);
  const firstBody = await blobs.get(downloads[0].url).text();
  assert.match(firstBody, /^[A-Za-z0-9+/]{43}=\n$/);
  assert.match(elements["public-key"].textContent, /^[A-Za-z0-9+/]{43}=$/);
  assert.ok(!Object.values(elements).some((node) => node.textContent === firstBody.trim()));

  elements["download-key-again"].onclick();
  assert.equal(downloads.length, 2);
  assert.equal(downloads[1].filename, downloads[0].filename);
  assert.equal(await blobs.get(downloads[1].url).text(), firstBody);

  elements["demo-type"].value = "ssn";
  elements["test-demo"].onclick();
  assert.equal(elements.regex.value, "\\b000-\\d{2}-\\d{4}\\b");
  assert.equal(elements.validation.value, "none");

  const originalGenerateKey = context.crypto.subtle.generateKey;
  context.crypto.subtle.generateKey = async () => { throw new Error("unsupported"); };
  await elements["generate-key"].onclick();
  assert.equal(elements["download-key-again"].disabled, true);
  assert.match(elements["key-status"].textContent, /Unable to generate key pair/);
  assert.equal(elements["public-key"].textContent, "Generate a pair to show the public key.");
  context.crypto.subtle.generateKey = originalGenerateKey;

  tabs[0].onkeydown({ key: "ArrowRight", preventDefault() {} });
  assert.equal(tabs[1].attributes["aria-selected"], "true");
  assert.equal(elements["toolkit-title"].textContent, "Synthetic Demo Data");
  assert.match(elements["toolkit-intro"].textContent, /safe, synthetic values/);
  assert.equal(context.document.title, "Synthetic Demo Data | DLP Demo Toolkit");
});


test("browser runtime handles copy reset, SSN handoff, key failure, and keyboard tabs", async () => {
  const source = await clientScript();
  assert.match(source, /const originalText=b\.textContent/);
  assert.match(source, /document\.getElementById\('regex'\)\.value=SSN_REGEX/);
  assert.match(source, /Unable to generate key pair in this browser/);
  assert.match(source, /\['ArrowLeft','ArrowRight','Home','End'\]/);
});
