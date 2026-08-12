# DLP custom profile + entries (v5 provider).
#
# In v5 the inline `entries` attribute on the profile is DEPRECATED. The current
# shape is: create the profile, then attach each detector as a standalone
# `cloudflare_zero_trust_dlp_entry` with profile_id + type = "custom".
#
# We key the entries with for_each by NAME so each is a stable, addressable
# resource (map key) rather than a content-hashed set element — this is what
# keeps re-applies idempotent (no destroy/recreate churn on the API-assigned
# entry_id). RE2 engine; validation = "luhn" is the only supported checksum.

resource "cloudflare_zero_trust_dlp_custom_profile" "cc" {
  count = local.dlp_ready ? 1 : 0

  account_id  = var.cloudflare_account_id
  name        = local.dlp_profile_name
  description = var.dlp_profile_description
}

resource "cloudflare_zero_trust_dlp_entry" "cc" {
  for_each = local.dlp_ready ? { for e in var.dlp_custom_entries : e.name => e } : {}

  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.cc[0].id
  type       = "custom"
  name       = each.value.name
  enabled    = try(each.value.enabled, true)

  # NOTE: the provider marks pattern.validation ("luhn") deprecated, but exposes
  # no replacement yet — it's a harmless plan-time warning, not drift. We keep it
  # because Luhn is core to weeding out false-positive card matches. Revisit when
  # the provider ships the successor field.
  pattern = merge(
    { regex = each.value.regex },
    try(each.value.validation, "none") != "none" ? { validation = each.value.validation } : {}
  )
}
