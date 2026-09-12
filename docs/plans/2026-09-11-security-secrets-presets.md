# Security and Secrets Presets Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add a categorized, high-confidence catalog of RE2-safe security and secret detectors to the DLP Regex Builder.

**Architecture:** Keep the existing single-module Worker and make its preset catalog and pure helpers importable by Node tests. Add category metadata and positive/negative fixtures to presets, render grouped selector options, and test the production catalog rather than duplicated logic.

**Tech Stack:** Cloudflare Workers JavaScript, Node.js built-in test runner/assertions, Wrangler, RE2-compatible regular expressions.

---

### Task 1: Test the production preset contract

**Objective:** Establish failing tests for catalog metadata, uniqueness, RE2 safety, and positive/negative matching.

**Files:**
- Create: `test/presets.test.mjs`
- Modify: `package.json`
- Test: `test/presets.test.mjs`

**Step 1: Write failing tests**

Import `PRESETS`, `scan`, and `re2Warnings` from `src/index.js`. Assert that each non-custom preset has `id`, `category`, `label`, `regex`, `sample`, `negativeSample`, and `note`; IDs are unique; every pattern has no RE2 warning; positive samples match; negative samples do not.

**Step 2: Run tests to verify failure**

Run: `node --test test/presets.test.mjs`
Expected: FAIL because production helpers are not exported and existing presets lack the required metadata.

**Step 3: Export production helpers only**

Add named exports for the existing catalog and pure helper functions without adding new presets yet.

**Step 4: Run tests again**

Run: `node --test test/presets.test.mjs`
Expected: FAIL on missing catalog metadata and security presets, proving the behavioral gap remains.

### Task 2: Add high-confidence secret presets

**Objective:** Make the catalog contract tests pass with constrained provider-specific patterns.

**Files:**
- Modify: `src/index.js:18-45`
- Test: `test/presets.test.mjs`

**Step 1: Add one provider category at a time**

Add Cloud providers, Source control, AI/API providers, Messaging, and Credentials/Infrastructure presets. Each preset includes synthetic positive and negative fixtures. Use only RE2-safe constructs and provider-specific prefixes or unmistakable structures.

**Step 2: Run the focused tests after each category**

Run: `node --test test/presets.test.mjs`
Expected: PASS after the final category, with all positive examples detected and all near-misses rejected.

**Step 3: Run existing regression tests**

Run: `npm test`
Expected: PASS for the new catalog suite and existing Luhn behavior.

### Task 3: Render categorized presets and guidance

**Objective:** Group presets by category and expose each preset's explanation in the UI.

**Files:**
- Modify: `src/index.js` HTML/CSS/client script
- Test: `test/presets.test.mjs`

**Step 1: Add a failing HTML test**

Assert that the generated HTML contains category option groups and a dedicated note element.

**Step 2: Run to verify failure**

Run: `node --test test/presets.test.mjs`
Expected: FAIL because the selector is currently flat and has no note element.

**Step 3: Implement grouped rendering**

Export `html`, group browser-side `PRESETS` by category into `<optgroup>` elements, add a note element, and update it in `applyPreset`.

**Step 4: Run tests**

Run: `npm test`
Expected: PASS.

### Task 4: Update user documentation

**Objective:** Document the expanded catalog, high-confidence trade-off, categories, and test workflow.

**Files:**
- Modify: `README.md`
- Modify: `package.json`

**Step 1: Update README**

Replace credit-card-only language with security/secrets catalog language while retaining the flagship loose-card explanation. Add a categorized preset table and explain that generic secret assignments are intentionally excluded.

**Step 2: Update test command**

Set `npm test` to run all `test/*.test.mjs` files with Node's test runner.

**Step 3: Run all tests**

Run: `npm test`
Expected: all tests pass without warnings or errors.

### Task 5: Add GCP and Azure credential presets

**Objective:** Cover stable, high-confidence Google Cloud and Azure credential formats without generic noisy matching.

**Files:**
- Modify: `src/index.js`
- Modify: `test/presets.test.mjs`

**Step 1: Add failing family fixtures**

Require Google OAuth `GOCSPX-`, Azure DevOps PAT with its fixed `AZDO` signature, contextual Azure Storage account keys, Azure Storage SAS, and contextual Microsoft Entra client secrets.

**Step 2: Verify RED**

Run: `node --test test/presets.test.mjs`
Expected: FAIL because the cloud credential presets are absent.

**Step 3: Add constrained patterns and metadata**

Implement only stable prefixes/signatures or contextual forms. Do not add generic arbitrary token or password patterns.

**Step 4: Verify GREEN**

Run: `node --test test/presets.test.mjs`
Expected: PASS with every positive and negative fixture checked individually.

### Task 6: Add authoritative Rust regex validation

**Objective:** Validate every preset and custom DLP rule with the same Rust regex syntax family documented by Cloudflare.

**Files:**
- Create: `rust-regex-validator/Cargo.toml`
- Create: `rust-regex-validator/src/lib.rs`
- Create: `scripts/build-regex-validator.sh`
- Create: `src/regex_validator.wasm`
- Modify: `src/index.js`
- Modify: `wrangler.toml`
- Modify: `terraform/worker.tf`
- Modify: `test/presets.test.mjs`

**Step 1: Add failing runtime tests**

Require `/scan` to return Rust validation status and useful diagnostics. Test valid Rust regex, malformed syntax, lookaround, backreferences, scoped flags, Unicode properties, Cloudflare's 1,024-byte pattern limit, and its prohibition on unbounded `+` and `*` quantifiers.

**Step 2: Verify RED**

Run the focused Node and Worker tests; expect failure because no authoritative validator exists.

**Step 3: Build the direct-ABI Wasm module**

Compile Rust `regex` in Docker for `wasm32-unknown-unknown`, exporting memory allocation, validation, and error retrieval functions. Keep Rust source and the generated artifact reproducible.

**Step 4: Integrate Worker and UI**

Import the precompiled Wasm module, instantiate it once at module scope, validate every submitted regex, and show compiler diagnostics in the existing builder UI. Keep heuristic warnings supplemental.

**Step 5: Wire Terraform**

Upload `src/regex_validator.wasm` as `application/wasm` alongside `index.js`; include both hashes in change detection.

**Step 6: Verify GREEN**

Run all tests, Wrangler dry run, Terraform validation, and live local HTTP probes.

### Task 7: Exercise the Worker locally

**Objective:** Prove the module runs in the Workers runtime and the new detector catalog works through HTTP.

**Files:**
- Verify: `src/index.js`
- Verify: `wrangler.toml`

**Step 1: Validate the deploy bundle**

Run: `npx wrangler deploy --dry-run`
Expected: successful bundle with no syntax or compatibility errors.

**Step 2: Start local Worker**

Run: `npx wrangler dev --local --port 8799`
Expected: Worker reports ready on `http://localhost:8799`.

**Step 3: Probe runtime endpoints**

Run requests against `/health`, `/`, and `/scan` using one positive and one near-miss secret fixture.
Expected: health returns `ok`; UI returns HTML containing categorized presets; scan detects only the positive fixture.

**Step 4: Review the final diff**

Verify no credentials, generated Wrangler state, Terraform state, or unrelated changes are staged. Preserve the pre-existing navigation edit in `src/index.js` as part of the working tree and call it out explicitly in the final report.
