variable "cloudflare_api_token" {
  description = "Cloudflare API token. Scopes: Account Zero Trust · Edit (DLP + Gateway) and Workers Scripts · Edit. Set in terraform.tfvars (gitignored)."
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID that owns the DLP profile, Gateway rule, and Worker."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for all resource names so it's obvious whose stack this is. Set \"\" to opt out."
  type        = string
  default     = "remo"
}

# ---- Worker (self-serve regex builder frontend) --------------------------

variable "deploy_worker" {
  description = "Deploy the DLP Regex Builder frontend Worker. The DLP profile/Gateway rule do NOT depend on it."
  type        = bool
  default     = true
}

variable "worker_name" {
  description = "Base name for the Worker script (name_prefix is prepended)."
  type        = string
  default     = "dlp-regex-builder"
}

variable "worker_compatibility_date" {
  description = "Workers compatibility date."
  type        = string
  default     = "2026-09-11"
}

variable "worker_hostname" {
  description = <<-EOT
    Custom hostname to serve the frontend at (e.g. "dlp-regex.itlinux.cc"). When
    set (and zone_id is provided), Terraform adds a per-hostname Workers route +
    a proxied AAAA DNS record — the SAFE pattern that does NOT touch other
    Workers/triggers on the zone. Leave "" to deploy the script only (reachable
    via workers.dev if enabled in the dashboard).
  EOT
  type        = string
  default     = ""
}

variable "zone_id" {
  description = "Zone ID for the domain in worker_hostname (e.g. itlinux.cc's zone). Required only when worker_hostname is set."
  type        = string
  default     = ""
}

# ---- DLP custom profile + entries ----------------------------------------

variable "deploy_dlp_profile" {
  description = "Create the DLP custom profile with the entries below."
  type        = bool
  default     = true
}

variable "dlp_profile_name" {
  description = "Display name of the DLP custom profile (name_prefix is prepended)."
  type        = string
  default     = "Credit Card (loose formatting)"
}

variable "dlp_profile_description" {
  description = "Description shown on the DLP custom profile. Max 100 chars (Cloudflare API limit, error 3302 if exceeded)."
  type        = string
  default     = "Catches CC numbers with loose space/dash separators the default PCI detector misses."

  validation {
    condition     = length(var.dlp_profile_description) <= 100
    error_message = "dlp_profile_description must be 100 characters or fewer (Cloudflare DLP API limit)."
  }
}

variable "dlp_custom_entries" {
  description = <<-EOT
    Regex entries for the DLP custom profile. Each: name, regex (Rust syntax),
    optional validation ("luhn" or "none"). The default catches 13-19 digit
    card numbers with loose space/dash separators (e.g. "1 344-4343 12345").
    Build/test new patterns in the Worker frontend, then paste the generated
    object here.
  EOT
  type = list(object({
    name       = string
    regex      = string
    validation = optional(string, "none")
    enabled    = optional(bool, true)
  }))
  default = [
    {
      name       = "CC 13-19 digits, loose separators"
      regex      = "\\b\\d(?:[ -]?\\d){12,18}\\b"
      validation = "luhn"
    },
  ]

  validation {
    condition     = alltrue([for entry in var.dlp_custom_entries : contains(["none", "luhn"], entry.validation)])
    error_message = "Each dlp_custom_entries validation must be \"none\" or \"luhn\"."
  }
}

# ---- Gateway HTTP policy (enforcement) -----------------------------------

variable "deploy_gateway_rule" {
  description = <<-EOT
    Create the Gateway HTTP policy that enforces the DLP profile. Default false:
    a Gateway block needs TLS inspection ON and should be tuned in monitor mode
    first. Flip to true when ready to enforce.
  EOT
  type        = bool
  default     = false
}

variable "gateway_rule_name" {
  description = "Name of the Gateway HTTP policy (name_prefix is prepended)."
  type        = string
  default     = "Block CC (loose) - DLP"
}

variable "gateway_rule_action" {
  description = "Gateway action: \"allow\" (monitor, with payload logging) or \"block\". Start with allow to tune false positives."
  type        = string
  default     = "allow"
  validation {
    condition     = contains(["allow", "block"], var.gateway_rule_action)
    error_message = "gateway_rule_action must be \"allow\" or \"block\"."
  }
}

variable "gateway_payload_log" {
  description = "Enable Gateway payload logging on the rule (requires an X25519 payload-encryption key configured in DLP settings)."
  type        = bool
  default     = false
}
