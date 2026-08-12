# dlp-cc-regex

A self-serve **DLP Regex Builder** (Cloudflare Worker frontend) + a **Terraform module** that deploys it alongside a Cloudflare **DLP custom profile** — built to catch credit-card numbers with *creative* formatting (e.g. `1 344-4343 12345`) that Cloudflare's default PCI detector misses.

```
┌─────────────────────────┐        ┌──────────────────────────────┐
│  Worker frontend         │  copy  │  Terraform module            │
│  (author + test regex)   ├───────▶│  DLP custom profile + entry  │
│  → RE2 pattern           │ tfvars │  (+ optional Gateway policy) │
│  → tfvars entry          │        │                              │
└─────────────────────────┘        └──────────────────────────────┘
```

## Why

Cloudflare's built-in credit-card DLP detector expects canonically grouped
numbers (4-4-4-4). Cards typed with odd separators slip past it:

```
1 344-4343 12345   ← 13 digits, weird grouping → default detector misses it
```

DLP custom entries run on the **RE2** engine (no lookahead, backreferences, or
checksum). So we split the job:

1. **RE2-safe regex** in the DLP entry — matches 13–19 digits where any pair may
   be separated by a single space or dash:
   ```
   \b\d(?:[ -]?\d){12,18}\b
   ```
2. **Luhn** — RE2 can't do it, so it's expressed as the entry's `validation`
   option. The Worker frontend runs Luhn in JS so you can *preview* real-vs-random matches while authoring.

## Two parts, one repo

### 1. Worker frontend — `src/index.js`
A dark self-serve page where a customer:
- picks a **preset** (loose CC ★ / canonical CC / custom) or writes any regex,
- tests it live against sample text,
- sees **RE2-unsupported warnings** (lookahead/backrefs) before they ship a pattern DLP would reject,
- optionally runs **Luhn** validation on matches,
- **copies** either the raw regex (for the dashboard) or a ready-made `dlp_custom_entries` tfvars object.

Endpoints: `GET /` (UI), `POST /scan`, `GET /api?regex=&text=&validation=luhn` (curl), `GET /health`.

Local dev:
```bash
npm run dev     # http://localhost:8787  (or: npx wrangler dev --port 8799 --local)
npm test        # regex + Luhn logic checks
```

### 2. Terraform module — `terraform/`
Provider `cloudflare/cloudflare ~> 5.0`. File layout follows the house conventions (providers / variables / naming / domain-split / outputs).

| File | Contents |
|---|---|
| `providers.tf` | provider + version pin |
| `variables.tf` | all variable declarations |
| `naming.tf` | `name_prefix` locals + readiness guards |
| `dlp.tf` | `cloudflare_zero_trust_dlp_custom_profile` with inline regex entries |
| `gateway.tf` | `cloudflare_zero_trust_gateway_policy` (enforcement, opt-in) |
| `worker.tf` | `cloudflare_workers_script` (the frontend) |
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

Verified `terraform plan` against the live account: **4 to add, 0 to change, 0
to destroy** (Worker, route, DNS record, DLP profile).

#### Idempotency (proven)
`apply` → `plan` returns **"No changes. Your infrastructure matches the
configuration."** — verified against the live account with two consecutive clean
plans. Three things make it stable:

- **`observability` is `ignore_changes`d** on the Worker — the v5 provider fills
  in `head_sampling_rate`/`logs`/`traces` itself and would otherwise diff every
  apply (same guard as the sibling `itlinux-landing` Worker).
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

Verified plan counts: default = **2** (Worker + DLP); `+deploy_gateway_rule` = **3**; with DLP off the Gateway rule correctly **skips** (guard engages, not a half-build).

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

## Files
```
src/index.js                     Worker (frontend + scan API)
test/luhn.test.mjs               logic tests
wrangler.toml, package.json      Worker dev/deploy
terraform/*.tf                   the module
terraform/terraform.tfvars.example
```
