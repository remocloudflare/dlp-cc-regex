# Security and Secrets Preset Catalog Design

## Goal

Expand the DLP Regex Builder from credit-card-focused presets into a practical, high-confidence security and secrets catalog while keeping every pattern compatible with Cloudflare DLP's RE2 engine.

## Scope

Retain the existing credit-card and custom presets. Add categorized presets for secret formats that have stable, provider-specific prefixes or unmistakable structure:

- **Cloud providers:** AWS access key IDs and Google API keys.
- **Source control:** GitHub personal, OAuth, user-to-server, refresh, and fine-grained tokens; GitLab personal/project/group access tokens.
- **AI and API providers:** OpenAI project/service/user keys, Anthropic API keys, and Stripe live secret/restricted keys.
- **Messaging:** Slack access tokens and Slack webhook URLs.
- **Credentials and infrastructure:** PEM private-key headers, compact JWTs, authenticated HTTP(S) URLs, and common database connection URLs containing credentials.

Generic matches such as arbitrary `password=`, `secret=`, or `token=` assignments are deliberately excluded because they produce too many false positives for the selected high-confidence posture.

## User Interface

Add a `category` property to each preset and render `<optgroup>` sections in the existing selector. Selecting a preset continues to populate its regex, validation, sample text, entry name, and explanatory note. Display the selected preset's note beneath the selector so users understand the detector's intended scope.

No new framework or build step is introduced. The Worker remains a single JavaScript module.

## Pattern Requirements

- Patterns must avoid lookaround, backreferences, atomic groups, and other RE2-unsupported constructs.
- Patterns should use literal provider prefixes and constrained alphabets/lengths wherever possible.
- Samples must use synthetic or documented nonfunctional values, never live credentials.
- Each preset needs a matching example and at least one near-miss that must not match.
- Credit-card presets retain optional Luhn validation; security presets use structural matching only.

## Testing

Export the preset catalog and scan helpers from `src/index.js` as named exports while preserving the default Worker export. Replace the standalone mirrored test logic with tests that import production code directly.

Tests will verify:

1. Every preset has a unique ID, category, label, regex, sample, and note.
2. Every security preset produces no RE2 compatibility warnings.
3. Every security preset matches its positive fixture.
4. Every security preset rejects its near-miss fixture.
5. Existing loose/canonical credit-card and Luhn behavior remains intact.
6. The generated page contains categorized option groups and preset guidance.

## Verification

Run the Node test suite, Wrangler dry-run/deploy validation, and a real local `wrangler dev` instance. Probe `/health`, `/`, and `/scan` to verify the Worker executes rather than relying only on static tests.

## Non-goals

- Entropy analysis or semantic secret scanning.
- Exhaustive coverage of every provider token format.
- Generic password/secret assignment detection.
- Automatic deployment to production; deployment remains a separate explicit action.
