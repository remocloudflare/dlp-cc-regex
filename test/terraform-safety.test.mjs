import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

const terraformDir = new URL("../terraform/", import.meta.url);
const terraformTest = existsSync(new URL("worker.tf", terraformDir)) ? test : test.skip;

terraformTest("Worker route explicitly depends on deployment and proxied DNS", async () => {
  const source = await readFile(new URL("worker.tf", terraformDir), "utf8");
  const route = source.match(/resource "cloudflare_workers_route" "builder" \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(route, "route resource not found");
  assert.match(
    route,
    /depends_on\s*=\s*\[\s*cloudflare_workers_deployment\.builder,\s*cloudflare_dns_record\.builder\s*\]/,
  );
});

terraformTest("DLP entry validation accepts only none or luhn", async () => {
  const source = await readFile(new URL("variables.tf", terraformDir), "utf8");
  const variable = source.match(/variable "dlp_custom_entries" \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(variable, "dlp_custom_entries variable not found");
  assert.match(
    variable,
    /condition\s*=\s*alltrue\(\[for entry in var\.dlp_custom_entries : contains\(\["none", "luhn"\], entry\.validation\)\]\)/,
  );
  assert.match(variable, /error_message[^\n]*none[^\n]*luhn/i);
});

test("README describes authoritative Rust scanning and validator ordering", async () => {
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  assert.doesNotMatch(readme, /JavaScript (?:RegExp )?(?:match )?preview|preview-only|global JavaScript preview/i);
  assert.match(readme, /Rust regex 1\.13\.1[^\n]*authoritative[^\n]*matching/i);
  assert.match(readme, /regex match first, then\s+applies the Luhn/i);
});
