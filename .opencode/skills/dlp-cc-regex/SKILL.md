---
name: dlp-cc-regex
description: Use when working on this Cloudflare DLP regex builder.
license: MIT
compatibility: Local use requires Node.js and Wrangler; Docker is only needed to rebuild WASM.
metadata:
  project: dlp-cc-regex
  owner: Remo Mattei
  opencode/autoinvoke: "true"
---

# DLP Regex Builder

Guidance for the Cloudflare DLP Regex Builder. This Worker provides high-confidence
security and secrets presets and validates and scans patterns with Rust regex in WASM.
Local Wrangler development is the default; Terraform is only for infrastructure and
production deployment.

## When to use

Load this skill for changes to:

- `src/index.js`, the preset catalog, `/scan`, or the browser UI.
- `src/regex-validator.js` or `src/regex_validator.wasm`.
- `rust-regex-validator/` or `scripts/build-regex-validator.sh`.
- Terraform Worker/DLP resources, README examples, screenshots, or production deployment.

## Project invariants

- Cloudflare DLP uses **Rust regex syntax**, not RE2 or JavaScript/PCRE syntax.
- Rust/WASM validation and matching are authoritative. Never execute user-supplied
  patterns with JavaScript `RegExp` on the server or in the Worker preview path.
- Enforce Cloudflare constraints before compiling: maximum 1,024 UTF-8 bytes and no
  unbounded `+` or `*` quantifiers. Use explicit bounded quantifiers.
- Preserve high-confidence detection. Prefer provider prefixes, fixed signatures,
  explicit context, bounded alphabets, and adversarial negative fixtures. Do not add
  generic `password=`, `secret=`, or `token=` detectors without explicit approval.
- Never commit real credentials, tokens, private keys, Terraform state, tfvars, or
  live secret material. Synthetic fixtures must be visibly nonfunctional.
- Keep the shared penguin background and attribution intact unless the user requests
  a visual change:
  `https://itlinux.cc/assets/bg.webp?v=5`
- Keep the footer bio accurate: Remo Mattei, Cloudflare One, Zero Trust, Workers,
  and Linux demos at itlinux.cc. Do not invent credentials or job titles.

## Catalog changes

Every non-custom preset must include:

- `id`, `category`, `label`, `regex`, `validation`, `note`.
- `positiveSamples` and `negativeSamples` with every claimed token family exercised.
- `sample` and `negativeSample` derived from those fixture arrays.
- Positive and negative tests for exact lengths, delimiters, embedded names, malformed
  suffixes, and allowed-alphabet continuations.

Security presets use `validation: "none"`. Credit-card presets may use `"luhn"`.
Keep category names stable because the UI renders them as option groups.

## Worker/API rules

- Read request bodies with the bounded streaming reader; reject oversized bodies
  before retaining them and cancel the reader when the limit is exceeded.
- Reject malformed JSON, `null`, arrays, non-object bodies, invalid UTF-8, unsupported
  methods, and unknown routes with the existing structured status contract.
- Keep `validation` limited to `none` or `luhn`; flags must remain exactly `g`.
- Limit regex, text, name, and query fields before Rust validation or matching.
- Preserve the request-generation/`AbortController` guard so an older `/scan` response
  cannot overwrite a newer preset selection.
- Escape dynamic HTML or use `textContent`; do not introduce an XSS path.
- Keep Rust scan results authoritative and preserve Luhn as a post-filter only.

## Local-first workflow

Do not require a remote Worker or Terraform to use the builder. The Worker is
stateless and has no bindings, so run it locally with Wrangler:

```bash
npm test
npx --yes wrangler@4.131.1 dev --local --port 8799
```

Open `http://localhost:8799/`. Verify `/health`, `/`, and `/scan` locally. The local
Worker includes the committed Rust WASM module and uses the same validation and scan
path as production. Stop the Wrangler process when finished.

Terraform is optional. Use it only when the user explicitly requests Cloudflare
infrastructure or a production update. A local UI/test task must not require
Terraform, run `terraform apply`, contact the remote Worker, or require Cloudflare
credentials. Users without Terraform can use the committed WASM artifact and the
local Wrangler workflow normally.

## Rust/WASM workflow

The pinned Rust dependency is `regex = 1.13.1`. The direct ABI exports memory,
allocation/deallocation, validation, error retrieval, and bounded scanning functions.

Rebuild through the repository script, not a host Rust installation:

```bash
./scripts/build-regex-validator.sh
```

Run it twice when changing Rust/WASM code and compare SHA-256 hashes. The generated
`src/regex_validator.wasm` is committed because Wrangler and Terraform deploy the
verified artifact. Update Rust source/tests and the artifact together.

## Verification loop

Before claiming a change is complete:

```bash
npm test
npx --yes wrangler@4.131.1 dev --local --port 8799
npx --yes wrangler@4.131.1 deploy --dry-run
```

If Terraform is installed and the task changes infrastructure, the plan must contain
no unexpected destroys. A normal Worker content update should be a new
`cloudflare_worker_version` and deployment, with the route ordered after the
deployment and proxied DNS record.

For runtime changes, start a real local Worker with Wrangler and probe `/`, `/health`,
and `/scan`. Test valid Rust syntax, malformed syntax, backreferences/lookaround,
oversized and chunked bodies, invalid validation/flags, `404`, and `405` behavior.

For UI changes, test desktop and mobile widths. Verify preset selection shows the
selected regex, note, and matches; specifically test switching quickly from the
credit-card preset to AWS so stale responses cannot restore card matches. Update
`docs/screenshots/` and README references when the user requests screenshots.

## Deployment and repository safety

- Deployment and Git publishing are separate operations.
- Do not run `terraform apply` blindly. Read the plan first and require zero
  unintended destroys. Preserve the existing Worker state migration.
- A production deployment targets `dlp-regex.itlinux.cc`; verify the live page,
  `/health`, and `/scan` after deployment.
- Git remotes are `origin` (public GitHub) and `gitlab` (private GitLab). Push the
  same verified commit to both when the user requests publishing.
- Before pushing, inspect staged paths and confirm no tfvars, tfstate, credentials,
  or generated local state is included.

## Known limitation

Cloudflare's provider currently warns that DLP `pattern.validation = "luhn"` is
deprecated but exposes no replacement. Keep the field for credit-card validation,
mention the warning in reports, and do not replace it with an invented attribute.
