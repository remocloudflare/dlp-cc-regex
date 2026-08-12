# Gateway HTTP policy that enforces the DLP profile.
# The DLP profile DETECTS; this policy ACTS (allow=monitor / block). It matches
# when the request payload trips any entry in our custom profile.
#
# Prerequisites for this to actually fire: TLS inspection ON, and (for reading
# matched content) a payload-encryption key configured in DLP settings.

resource "cloudflare_zero_trust_gateway_policy" "cc_block" {
  count = local.gateway_ready ? 1 : 0

  account_id  = var.cloudflare_account_id
  name        = local.gateway_rule_name
  description = "Enforces the ${local.dlp_profile_name} DLP profile on HTTP uploads."
  action      = var.gateway_rule_action
  enabled     = true
  filters     = ["http"]

  traffic = "any(dlp.profiles[*] in {\"${cloudflare_zero_trust_dlp_custom_profile.cc[0].id}\"})"

  rule_settings = {
    payload_log = {
      enabled = var.gateway_payload_log
    }
  }
}
