# DLP Demo Toolkit Design

**Goal:** Extend the existing DLP Regex Builder into a single-page demo toolkit that retains the regex workflow while adding safe synthetic DLP data and Cloudflare-compatible payload-logging key generation.

## Existing behavior to preserve

- Keep every current regex preset, Rust/Wasm validation path, scan API, copy action, responsive 40/60 desktop layout, single-column mobile layout, navigation, background, attribution, and Cloudflare deployment behavior.
- Keep long match and generated output wrapping.

## Page structure

Add a compact toolkit selector near the top of the main content with three panels:

1. **Regex Builder** — existing four-step workflow, unchanged.
2. **Synthetic Demo Data** — configurable safe test data generation.
3. **Payload Logging Keys** — browser-local X25519 key generation.

Only one toolkit panel is primary at a time to avoid making the existing page excessively long. The selected panel uses the existing orange accent and remains keyboard accessible.

## Synthetic demo data

Controls:

- Data type: **Credit cards** or **SSNs**.
- Quantity: integer from 1 through 100; default 10.
- Generate button.
- Copy one, Copy all, and **Test in Regex Builder** actions.

Credit-card behavior:

- Generate Luhn-valid numbers using documented payment-network test BINs rather than random production-looking account ranges.
- Label all output as synthetic test data.
- Support plain, spaces, dashes, and mixed-separator formatting so the existing loose credit-card detector can be demonstrated.
- Never claim the numbers are usable payment credentials.

SSN behavior:

- Generate only deliberately invalid/reserved examples using area `000`, which SSA does not assign.
- Format as `000-XX-XXXX` with randomized non-sensitive group/serial digits.
- Label all output as synthetic and non-issued.

Generated values exist only in page memory. They are never sent to a Worker endpoint unless the user explicitly selects **Test in Regex Builder**, which places them into the existing local scan textarea and runs the existing `/scan` call.

## Payload logging key pair

- Generate an X25519 key pair entirely in the browser using audited Web Crypto-compatible code bundled with the Worker; no third-party runtime network dependency.
- Export exactly the bare 32-byte public and private key values as standard padded base64, matching `matched-data-cli generate-key-pair` output—not PEM.
- Display only the public key with a copy action.
- Immediately download the private key after generation as:
  `cloudflare-payload-logging-private-key-YYYYMMDD-HHMMSS.txt`
- The downloaded file contains only the bare base64 private key plus a trailing newline so it can be passed directly to `matched-data-cli` workflows.
- Do not display the private key in the DOM, return it from the Worker, log it, or store it in cookies, localStorage, sessionStorage, IndexedDB, Cache API, analytics, or URL state.
- Retain the private key only in a JavaScript in-memory variable for the active page lifetime so **Download again** works. Clear the reference when a new pair is generated or the page unloads.
- Show: “Private key downloaded. Cloudflare cannot recover it; store it securely.”
- Link to Cloudflare’s official key-generation documentation and show the CLI fallback:
  `./matched-data-cli generate-key-pair`

## Compatibility and security validation

- Add deterministic tests proving exported keys are exactly 32 bytes and standard padded base64.
- Verify a browser-generated key pair interoperates with `matched-data-cli` encryption/decryption behavior before release.
- Add source tests prohibiting private-key DOM rendering, storage APIs, network submission, and logging.
- Add browser tests that generation triggers one download, the public key is shown, private key text is absent from the page, and **Download again** reproduces the same file while the page remains open.
- Use synthetic fixtures constructed from fragments where necessary so repository secret scanners do not treat them as live credentials.

## Responsive behavior

- Preserve the current 40/60 desktop grid inside Regex Builder.
- Toolkit selector becomes horizontally scrollable on narrow screens rather than compressing labels.
- Synthetic data and key panels use the same card system and collapse to one column below 920px.
- Long generated values wrap without horizontal page overflow.

## Release

- Implement on both `local` and `terraform` branches.
- Run the complete Node/Wasm test suite, browser JavaScript checks, Wrangler dry run, real local Worker, and desktop/mobile visual verification.
- Deploy surgically to the existing `remo-dlp-regex-builder` Worker without reconciling routes or DNS.
- Verify the custom domain and private-key download in a real browser, then push both branches.
