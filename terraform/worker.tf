# The installed Cloudflare provider 5.23 schema exposes multi-file uploads on
# cloudflare_worker_version.modules (not cloudflare_workers_script). Keep the
# Wasm as its own application/wasm module rather than embedding it in JavaScript.
resource "cloudflare_worker" "builder" {
  count = local.worker_ready ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = local.worker_name

  observability = {
    enabled = true
  }
}

resource "cloudflare_worker_version" "builder" {
  count = local.worker_ready ? 1 : 0

  account_id         = var.cloudflare_account_id
  worker_id          = cloudflare_worker.builder[0].id
  main_module        = "index.js"
  compatibility_date = var.worker_compatibility_date

  annotations = {
    workers_message = "DLP regex builder ${local.worker_content_sha256}"
    workers_tag     = local.worker_content_sha256
  }

  modules = [
    {
      name         = "index.js"
      content_file = local.worker_bundle
      content_type = "application/javascript+module"
    },
    {
      name         = "regex-validator.js"
      content_file = local.worker_validator
      content_type = "application/javascript+module"
    },
    {
      name         = "regex_validator.wasm"
      content_file = local.worker_validator_wasm
      content_type = "application/wasm"
    },
  ]
}

resource "cloudflare_workers_deployment" "builder" {
  count = local.worker_ready ? 1 : 0

  account_id  = var.cloudflare_account_id
  script_name = cloudflare_worker.builder[0].name
  strategy    = "percentage"

  versions = [{
    version_id = cloudflare_worker_version.builder[0].id
    percentage = 100
  }]
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
  script  = cloudflare_worker.builder[0].name

  depends_on = [cloudflare_workers_deployment.builder, cloudflare_dns_record.builder]
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

  depends_on = [cloudflare_workers_deployment.builder]
}
