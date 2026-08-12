# The self-serve DLP Regex Builder frontend, deployed as a Workers script.
# It's a single ESM module (../src/index.js) — no bundler/build step needed.
#
# content_file REQUIRES content_sha256 in the v5 provider.

resource "cloudflare_workers_script" "builder" {
  count = local.worker_ready ? 1 : 0

  account_id     = var.cloudflare_account_id
  script_name    = local.worker_name
  content_file   = local.worker_bundle
  content_sha256 = filesha256(local.worker_bundle)
  main_module    = "index.js"

  compatibility_date = var.worker_compatibility_date

  observability = {
    enabled = true
  }

  # The CF v5 provider returns extra observability sub-fields
  # (head_sampling_rate, logs, traces) that aren't declared above, which would
  # otherwise cause a perpetual diff on every apply. Ignore the whole block —
  # we only care that observability is enabled. Keeps the module idempotent.
  lifecycle {
    ignore_changes = [observability]
  }
}

# --- Custom-hostname routing (SAFE per-hostname pattern) ------------------
# A per-hostname Workers route + a proxied AAAA record. This mirrors the
# itlinux-pac approach and does NOT replace any zone-wide triggers, so the
# other Workers on the zone (landing, mesh, pac, email-router, ...) are
# untouched. Only builds when worker_hostname + zone_id are set.

resource "cloudflare_workers_route" "builder" {
  count = local.hostname_ready ? 1 : 0

  zone_id = var.zone_id
  pattern = "${var.worker_hostname}/*"
  script  = cloudflare_workers_script.builder[0].script_name
}

# Proxied AAAA 100:: is the standard placeholder for a proxied Workers hostname.
resource "cloudflare_dns_record" "builder" {
  count = local.hostname_ready ? 1 : 0

  zone_id = var.zone_id
  name    = var.worker_hostname
  type    = "AAAA"
  content = "100::"
  ttl     = 1
  proxied = true
}
