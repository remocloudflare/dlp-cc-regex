output "dlp_profile_id" {
  description = "ID of the DLP custom profile — reference it in Gateway HTTP policies."
  value       = local.dlp_ready ? cloudflare_zero_trust_dlp_custom_profile.cc[0].id : null
}

output "dlp_profile_name" {
  description = "Display name of the DLP custom profile."
  value       = local.dlp_ready ? local.dlp_profile_name : null
}

output "gateway_rule_id" {
  description = "ID of the Gateway HTTP policy enforcing the profile (null if not deployed)."
  value       = local.gateway_ready ? cloudflare_zero_trust_gateway_policy.cc_block[0].id : null
}

output "worker_name" {
  description = "Deployed Worker script name (null if not deployed)."
  value       = local.worker_ready ? cloudflare_worker.builder[0].name : null
}

output "worker_url" {
  description = "Live URL of the builder frontend (custom hostname when configured, else workers.dev hint)."
  value = local.hostname_ready ? "https://${var.worker_hostname}/" : (
    local.worker_ready ? "https://${local.worker_name}.<your-subdomain>.workers.dev (enable workers.dev or set worker_hostname)" : null
  )
}

output "dashboard_links" {
  description = "Where to view/manage these resources in the Cloudflare dashboard."
  value = {
    dlp_profiles = "https://one.dash.cloudflare.com/${var.cloudflare_account_id}/dlp/profiles"
    gateway_http = "https://one.dash.cloudflare.com/${var.cloudflare_account_id}/gateway/firewall-policies"
    worker       = local.worker_ready ? "https://dash.cloudflare.com/${var.cloudflare_account_id}/workers/services/view/${local.worker_name}" : null
  }
}
