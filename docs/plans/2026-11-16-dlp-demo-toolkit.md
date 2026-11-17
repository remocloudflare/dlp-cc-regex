# DLP Demo Toolkit Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add browser-local Cloudflare payload-logging key generation and safe synthetic credit-card/SSN demo data to the existing DLP Regex Builder without changing its existing regex behavior.

**Architecture:** Keep the Worker stateless and the existing `/scan` API unchanged. Add pure JavaScript data-generation and X25519 export helpers that are exercised in Node and bundled into the existing inline page; browser controls call those helpers locally, with the private key retained only in closure memory and downloaded immediately. Extend the existing card system with an accessible three-tab toolkit shell while preserving the 40/60 regex layout and mobile breakpoint.

**Tech Stack:** Cloudflare Workers module, inline HTML/CSS/JavaScript, Web Crypto/X25519-compatible implementation, Node test runner, Rust/Wasm regex validator, Wrangler.

---

### Task 1: Add synthetic demo-data helpers

**Objective:** Generate bounded batches of Luhn-valid test cards and reserved/non-issued SSNs with deterministic injectable randomness.

**Files:**
- Modify: `src/index.js`
- Create: `test/demo-data.test.mjs`

**Steps:**
1. Write failing tests for quantity bounds, Luhn-valid test cards, formatting variants, `000-XX-XXXX` SSNs, and deterministic output with injected random bytes.
2. Run `node --experimental-wasm-modules --disable-warning=ExperimentalWarning --test test/demo-data.test.mjs`; expect failures because helpers do not exist.
3. Implement pure exported helpers for credit-card and SSN generation, using documented test BINs and area `000` only.
4. Re-run the focused test, then `npm test`; expect all tests to pass.

### Task 2: Add Cloudflare-compatible X25519 key export

**Objective:** Generate 32-byte X25519 public/private keys and export them as standard padded base64 compatible with `matched-data-cli`.

**Files:**
- Modify: `src/index.js`
- Create: `test/payload-key.test.mjs`
- Add only if required: a small vendored, audited X25519 helper module under `src/`

**Steps:**
1. Write failing tests for 32-byte public/private exports, padded standard base64, unique generation, and known-vector public-key derivation.
2. Run the focused test and verify the expected failure.
3. Implement the minimal local-only helper with no runtime network dependency.
4. Add an interoperability test using an installed/downloaded pinned `matched-data-cli` release or its published algorithm vectors; prove generated keys work with its encrypt/decrypt workflow.
5. Run focused and full tests.

### Task 3: Build the accessible toolkit UI

**Objective:** Add Regex Builder, Synthetic Demo Data, and Payload Logging Keys panels without regressing the current interface.

**Files:**
- Modify: `src/index.js`
- Modify: `test/worker-hardening.test.mjs`

**Steps:**
1. Add failing HTML/source tests for tabs, ARIA state, synthetic controls, public-key output, official docs/CLI fallback, and mobile behavior.
2. Add failing security assertions that private key values are never inserted into HTML, storage APIs, logs, URLs, fetch bodies, or Worker responses.
3. Implement the selector and panels using current cards and orange selected state.
4. Keep Regex Builder’s current DOM and behavior intact inside its panel.
5. Wire quantity/type/format generation, Copy one/all, and Test in Regex Builder.
6. Run focused and full tests.

### Task 4: Implement automatic private-key download

**Objective:** Download the bare base64 private key immediately and support in-memory re-download without exposing it elsewhere.

**Files:**
- Modify: `src/index.js`
- Create: `test/client-runtime.test.mjs` or extend the existing browser-runtime harness

**Steps:**
1. Write a failing runtime test that clicks Generate and asserts exactly one text-file download, padded base64 plus newline, timestamped filename, visible public key, and no private key in page text.
2. Assert Download again yields the same file during the active page session.
3. Implement closure-only private-key retention, Blob/object-URL download, URL revocation, and unload cleanup.
4. Re-run runtime and full tests.

### Task 5: Browser and responsive verification

**Objective:** Prove the complete page works at desktop and mobile widths.

**Files:**
- Update screenshots only if the repository’s screenshot contract requires it.

**Steps:**
1. Run `npm run dev` and open the local Worker in a real browser.
2. Verify each toolkit tab, keyboard operation, card/SSN quantities, copy actions, Test in Regex Builder, key generation, automatic download, and download-again.
3. Verify desktop 40/60 Regex Builder layout and no horizontal overflow with Slack.
4. Verify one-column mobile layout and horizontally scrollable toolkit tabs.
5. Inspect the downloaded file and compare its public-key derivation with the displayed public key.

### Task 6: Release both branches and the live Worker

**Objective:** Publish matching source and update only the existing custom-domain Worker.

**Files:**
- `local` branch source/tests/docs
- `terraform` branch source/tests/docs

**Steps:**
1. Run `npm test`, `node --check src/index.js`, inline client-script checks, and `wrangler deploy --dry-run` on both branches.
2. Cherry-pick the implementation commits onto `terraform` and rerun all 62+ tests including Terraform safety tests.
3. Surgically deploy to `remo-dlp-regex-builder` with `--keep-vars`, `workers_dev=false`, and `preview_urls=false`; do not alter routes or DNS.
4. Verify `https://dlp-regex.itlinux.cc/` in a real browser, including a fresh automatic private-key download and synthetic-data scan.
5. Push `local` and `terraform`, then verify remote SHAs match the tested commits.
