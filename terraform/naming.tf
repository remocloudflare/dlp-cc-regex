locals {
  name_prefix = var.name_prefix != "" ? "${var.name_prefix}-" : ""

  worker_name       = "${local.name_prefix}${var.worker_name}"
  dlp_profile_name  = "${local.name_prefix}${var.dlp_profile_name}"
  gateway_rule_name = "${local.name_prefix}${var.gateway_rule_name}"

  worker_bundle         = "${path.module}/../src/index.js"
  worker_validator      = "${path.module}/../src/regex-validator.js"
  worker_validator_wasm = "${path.module}/../src/regex_validator.wasm"
  worker_content_sha256 = sha256(join(":", [
    filesha256(local.worker_bundle),
    filesha256(local.worker_validator),
    filesha256(local.worker_validator_wasm),
  ]))

  # Readiness guards — a pillar only builds when its flag is on AND it has content.
  dlp_ready    = var.deploy_dlp_profile && length(var.dlp_custom_entries) > 0
  worker_ready = var.deploy_worker
  # Gateway rule needs the DLP profile to reference.
  gateway_ready = var.deploy_gateway_rule && local.dlp_ready
  # Custom-hostname routing needs the worker + a hostname + a zone.
  hostname_ready = local.worker_ready && var.worker_hostname != "" && var.zone_id != ""
}
