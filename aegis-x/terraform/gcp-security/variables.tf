variable "project_id" {
  description = "Project that hosts the Pub/Sub topic, log bucket and KMS key (the security/logging project)."
  type        = string
}

variable "organization_id" {
  description = "Numeric organization ID. Required when SCC notifications, the org-level sink or org-level org policies are enabled."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_id == "" || can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must be numeric."
  }
}

variable "region" {
  description = "Location for the bucket, key ring and provider default."
  type        = string
  default     = "us-central1"
}

variable "name_prefix" {
  description = "Prefix for created resource names."
  type        = string
  default     = "aegis-x"
}

variable "labels" {
  description = "Labels applied to supporting resources."
  type        = map(string)
  default     = { app = "aegis-x" }
}

# ---- Feature gates (all off: nothing is created until explicitly enabled) ----

variable "enable_scc_notifications" {
  description = "Create the Pub/Sub topic and the SCC organization notification config. Requires organization_id and SCC activated on the org."
  type        = bool
  default     = false
}

variable "enable_audit_log_sink" {
  description = "Create the Cloud Audit Logs sink, CMEK-encrypted bucket and KMS key."
  type        = bool
  default     = false
}

variable "enable_org_policies" {
  description = "Apply the boolean org-policy constraints listed in org_policy_constraints."
  type        = bool
  default     = false
}

# ---- SCC notifications ----

variable "scc_notification_filter" {
  description = "SCC findings filter for the notification stream."
  type        = string
  default     = "state=\"ACTIVE\" AND NOT mute=\"MUTED\" AND (severity=\"CRITICAL\" OR severity=\"HIGH\")"
}

variable "pubsub_message_retention" {
  description = "Topic message retention (duration string)."
  type        = string
  default     = "86400s"
}

# ---- Audit log sink ----

variable "audit_sink_scope" {
  description = "\"organization\" (all child projects; needs organization_id) or \"project\" (project_id only)."
  type        = string
  default     = "project"

  validation {
    condition     = contains(["organization", "project"], var.audit_sink_scope)
    error_message = "audit_sink_scope must be \"organization\" or \"project\"."
  }
}

variable "audit_log_filter" {
  description = "Log filter for the sink. Admin Activity logs are always on; Data Access logs must be enabled separately (and are billable)."
  type        = string
  default     = "logName:\"cloudaudit.googleapis.com\""
}

variable "log_retention_days" {
  description = "Bucket retention period in days (unlocked; locking is irreversible and deliberately not done here)."
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 1
    error_message = "log_retention_days must be at least 1."
  }
}

variable "kms_key_rotation_period" {
  description = "Rotation period of the created CMEK key (seconds, e.g. 7776000s = 90 days)."
  type        = string
  default     = "7776000s"
}

variable "kms_key_id" {
  description = "Existing CMEK key ID to use instead of creating one (must be in the same location as the bucket/topic; service agents need encrypter/decrypter on it)."
  type        = string
  default     = ""
}

# ---- Org policy ----

variable "org_policy_parent" {
  description = "Where org policies attach: \"organizations/<id>\", \"folders/<id>\" or \"projects/<id>\"."
  type        = string
  default     = ""

  validation {
    condition     = var.org_policy_parent == "" || can(regex("^(organizations|folders|projects)/[^/]+$", var.org_policy_parent))
    error_message = "org_policy_parent must look like organizations/123, folders/123 or projects/my-project."
  }
}

variable "org_policy_constraints" {
  description = "Boolean constraints to enforce. Defaults are widely-used hardening constraints that rarely break workloads; review each against your estate before enabling. constraints/iam.disableServiceAccountKeyCreation is a common opt-in but can break existing key-based automation."
  type        = list(string)
  default = [
    "constraints/storage.uniformBucketLevelAccess",
    "constraints/storage.publicAccessPrevention",
    "constraints/compute.requireOsLogin",
    "constraints/compute.disableSerialPortAccess",
    "constraints/compute.skipDefaultNetworkCreation",
    "constraints/sql.restrictPublicIp",
  ]

  validation {
    condition     = alltrue([for c in var.org_policy_constraints : can(regex("^constraints/[A-Za-z0-9_.]+$", c))])
    error_message = "Each constraint must look like constraints/<service>.<name>."
  }
}
