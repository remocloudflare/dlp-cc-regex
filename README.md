# dlp-cc-regex

A self-serve **DLP Regex Builder** (Cloudflare Worker frontend) + a **Terraform module** that deploys it alongside a Cloudflare **DLP custom profile** — built to catch credit-card numbers with *creative* formatting (e.g. `1 344-4343 12345`) that Cloudflare's default PCI detector misses.

```
┌─────────────────────────┐        ┌──────────────────────────────┐
│  Worker frontend         │  copy  │  Terraform module            │
│  (author + test regex)   ├───────▶│  DLP custom profile + entry  │
│  → Rust regex pattern    │ tfvars │  (+ optional Gateway policy) │
│  → tfvars entry          │        │                              │
└─────────────────────────┘        └──────────────────────────────┘
```

## Why

Cloudflare's built-in credit-card DLP detector expects canonically grouped
numbers (4-4-4-4). Cards typed with odd separators slip past it:

```
1 344-4343 12345   ← 13 digits, weird grouping → default detector misses it
```

DLP custom entries use **Rust regex syntax** (no lookaround, backreferences, or
checksum). So we split the job:

1. **Rust regex** in the DLP entry — matches 13–19 digits where any pair may
   be separated by a single space or dash:
   ```
   \b\d(?:[ -]?\d){12,18}\b
   ```
2. **Luhn** — regex cannot do it, so it is expressed as the entry's `validation`
   option. The Worker performs the authoritative Rust regex match first, then
   applies the Luhn post-filter to each matched substring.

## Two parts, one repo

### 1. Worker frontend — `src/index.js`
A dark self-serve page where a customer:
- picks a categorized **high-confidence preset** or **Custom** and sees the preset's detection note,
- tests it live against sample text,
- uses Rust regex 1.13.1 compiled to WebAssembly for authoritative validation and matching,
- sees Cloudflare's 1,024-byte and bounded-quantifier constraints separately,
- displays match text and offsets returned by the Rust engine,
- optionally runs **Luhn** validation on matches,
- **copies** either the raw regex (for the dashboard) or a ready-made `dlp_custom_entries` tfvars object.

The catalog deliberately favors recognizable prefixes and bounded assignment
contexts over generic `secret=...` matching. Generic assignments are excluded:
they are too noisy for a high-confidence production posture. Several regexes
consume an allowed trailing delimiter because Rust regex has no lookaround; the
note shown for each preset calls this out where relevant.

#### Preset catalog

| Category | Presets |
|---|---|
| Financial data | Credit card (loose separators) ★; Credit card (canonical 4-4-4-4) |
| Cloud providers | AWS access key ID; Google API key; Google OAuth client secret; Azure Storage account key; Azure Storage shared access signature; Microsoft Entra client secret |
| Source control | Azure DevOps personal access token; GitHub classic token families; GitHub fine-grained PAT; GitLab personal access token |
| AI and API providers | OpenAI project/service-account key; OpenAI user key; Anthropic API key; Stripe live secret/restricted key |
| Messaging | Slack access token; Slack incoming webhook URL |
| Credentials and infrastructure | PEM private-key header; compact JWT; authenticated HTTP(S) URL; database URL with credentials |
| Custom | Custom (write your own) |

#### HTTP contract and limits

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | `GET` | Builder UI |
| `/health` | `GET` | Plain `ok` health response |
| `/api?regex=&text=&validation=` | `GET` | Curl-friendly scan |
| `/scan` | `POST` | JSON scan API |

Known paths reject unsupported methods with `405` and `Allow`; unknown paths
return `404`. `/scan` requires a JSON object and rejects malformed JSON, null,
arrays, and non-JSON content. Limits are **128 KiB request body**, **1,024 UTF-8
bytes regex**, **64 KiB sample text**, and **256 UTF-8 bytes entry name**.
`validation` is only `none` or `luhn`; `flags` is only `g`. Matching always uses
the bounded Rust Wasm scanner. Case/multiline/dotall behavior must be expressed as
inline Rust flags in the DLP pattern, for example `(?i:foo)`.

Local dev:
```bash
npm run dev     # local-only: http://localhost:8799 (no Terraform or CF credentials)
npm test        # catalog, API limits/routes, HTML script/ID, Rust/Wasm, and Luhn checks
./scripts/build-regex-validator.sh  # reproducible Docker Wasm build
npm run dev:remote                  # optional remote dev session; requires CF auth
npx --yes wrangler@4.131.1 deploy --dry-run  # package without publishing
```

The local builder is stateless and includes the committed Rust/WASM validator.
Terraform is not needed for local development; use it only for Cloudflare
infrastructure or production deployment.

#### Deploy your own Worker only

The regex builder can be deployed independently without Terraform or DLP account changes:

```bash
git clone https://github.com/remocloudflare/dlp-cc-regex.git
cd dlp-cc-regex
npm test
npx wrangler login
npx --yes wrangler@4.131.1 deploy --dry-run
npm run deploy
```

This publishes the stateless builder and its committed Rust/Wasm validator to your authenticated Cloudflare account. It does not create a DLP profile, Gateway policy, DNS record, route, or custom hostname. Use the Terraform module below only when you intentionally want those account-side resources; copy `terraform.tfvars.example`, supply your own account/zone values, and keep tokens and state out of Git.

### 2. Terraform module — `terraform/`
Provider `cloudflare/cloudflare ~> 5.0`. File layout follows the house conventions (providers / variables / naming / domain-split / outputs).

| File | Contents |
|---|---|
| `providers.tf` | provider + version pin |
| `variables.tf` | all variable declarations |
| `naming.tf` | `name_prefix` locals + readiness guards |
| `dlp.tf` | `cloudflare_zero_trust_dlp_custom_profile` with inline regex entries |
| `gateway.tf` | `cloudflare_zero_trust_gateway_policy` (enforcement, opt-in) |
| `worker.tf` | versioned Worker modules and deployment (JavaScript + separate Wasm module) |
| `outputs.tf` | ids, dashboard links, verify hints |

#### Deploy
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in token + account id
export CLOUDFLARE_API_TOKEN="$(…)"             # optional; token is also read from tfvars
terraform init
terraform apply
```
> **Shell note (nushell):** `$env.CLOUDFLARE_API_TOKEN = (open ~/.config/cloudflare/api-token | str trim)`

#### Hosting on itlinux.cc
This module is pre-wired for the **ciaoremo** account / **itlinux.cc** zone. The
checked-out `terraform.tfvars` (gitignored) already points at:

- account `815b94af…` (ciaoremo)
- zone `2503e0d9…` (itlinux.cc)
- hostname **`dlp-regex.itlinux.cc`**

It uses the **safe per-hostname pattern**: a `cloudflare_workers_route` for
`dlp-regex.itlinux.cc/*` + a proxied `AAAA 100::` DNS record. This is the same
approach as `itlinux-pac` and does **NOT** replace any zone-wide triggers, so
the other Workers on the zone (`itlinux-landing`, `itlinux-mesh`, `itlinux-pac`,
`itlinux-email-router`, …) are untouched.

The Worker is uploaded through the provider's versioned module API. `index.js`,
`regex-validator.js`, and `regex_validator.wasm` are separate modules; the Wasm
module is sent as `application/wasm`, and a combined source hash tags each version.
The proxied DNS record depends on the 100% Worker deployment, and the route
depends on both that deployment and the DNS record. A first apply therefore
cannot create the route before its active Worker and required proxied DNS exist.

#### Idempotency
Two things keep the DLP resources stable:
- **DLP entries are standalone `cloudflare_zero_trust_dlp_entry` resources**
  (the inline `entries` attribute on the profile is deprecated in v5). They're
  attached with `for_each` **keyed by name**, so each entry is a stable map
  element — not a content-hashed set element that would churn on the
  API-assigned `entry_id`.
- **Profile `description` is capped at 100 chars** (a `variable` `validation`
  enforces it). The Cloudflare DLP API rejects longer strings with error 3302
  ("string too long") — hit for real during the first apply.

Known harmless warning: the provider marks `pattern.validation = "luhn"`
deprecated but ships no replacement yet. It's a plan-time warning only (no
drift); we keep it because Luhn is core to filtering false-positive card matches.

The validator and bounded scanner use the pinned Rust `regex` 1.13.1 crate
compiled to a standalone Wasm module. Rust is authoritative for both syntax and
matching; no user-supplied pattern is executed by JavaScript `RegExp`. Builds run
in Docker, and release verification builds twice and compares SHA-256 hashes.
Cloudflare constraints are enforced before invoking Wasm, including the
1,024-byte regex limit and bounded quantifiers.

To host it elsewhere, set `worker_hostname` + `zone_id` (or leave both `""` for
a script-only deploy reachable via workers.dev).

#### Staging flags (default OFF where risky)

| Flag | Default | Effect |
|---|---|---|
| `deploy_worker` | `true` | deploy the builder frontend Worker |
| `deploy_dlp_profile` | `true` | create the DLP custom profile + entries |
| `deploy_gateway_rule` | `false` | create the Gateway HTTP policy that **enforces** the profile |
| `gateway_rule_action` | `allow` | `allow` (monitor) → `block` once tuned |
| `gateway_payload_log` | `false` | needs an X25519 key in DLP settings |

With DLP off the Gateway rule correctly skips (guard engages, not a half-build).

## API token scopes
- **Account · Zero Trust · Edit** (DLP profile + Gateway policy)
- **Account · Workers Scripts · Edit** (the frontend Worker)

## Wiring: two halves of ONE rule
- **DLP profile / custom entry** = *what* is sensitive (the regex). `dlp.tf`.
- **Gateway HTTP policy** = *what to do about it* (allow/block), references the profile. `gateway.tf`.

Prereqs for the Gateway rule to actually fire: **TLS inspection ON**. Start with
`gateway_rule_action = "allow"` + payload logging to tune false positives, then
switch to `block`.

## Adding a new pattern (the intended loop)
1. Open the Worker frontend, write/test your regex, pick validation.
2. Click **Copy tfvars entry**.
3. Paste the object into `dlp_custom_entries` in `terraform.tfvars`.
4. `terraform apply`.

## Live preview

The builder is live at [dlp-regex.itlinux.cc](https://dlp-regex.itlinux.cc/).
The screenshots below were captured from the deployed Worker at desktop and mobile widths.

![DLP Regex Builder desktop](docs/screenshots/dlp-regex-builder-desktop.png)

![DLP Regex Builder mobile](docs/screenshots/dlp-regex-builder-mobile.png)

## Files
```
src/index.js                     Worker (frontend + scan API)
src/regex-validator.js           Wasm ABI + Cloudflare constraints
src/regex_validator.wasm         generated Rust regex validator
rust-regex-validator/            pinned Rust source and Cargo lock
scripts/build-regex-validator.sh Docker-based reproducible build
test/*.test.mjs                  catalog, scan, Rust validation, and Luhn tests
wrangler.toml, package.json      Worker dev/deploy
terraform/*.tf                   the module
terraform/terraform.tfvars.example
```
