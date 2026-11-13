variable "subscription_id" {
  description = "Target Azure subscription GUID. Null falls back to ARM_SUBSCRIPTION_ID."
  type        = string
  default     = null
}

variable "location" {
  description = "Azure region for the resource group and Log Analytics workspace."
  type        = string
  default     = "westeurope"
}

variable "environment" {
  description = "Environment tag value."
  type        = string
  default     = "sandbox"
}

variable "resource_group_name" {
  description = "Resource group created to hold the workspace."
  type        = string
  default     = "rg-aegisx-security"
}

variable "workspace_name" {
  description = "Log Analytics workspace name (4-63 chars)."
  type        = string
  default     = "law-aegisx-security"
}

variable "retention_in_days" {
  description = "Workspace retention in days (30-730). Interactive retention beyond 31 days is billed."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "retention_in_days must be between 30 and 730."
  }
}

variable "daily_quota_gb" {
  description = "Daily ingestion cap in GB (cost guard). -1 disables the cap."
  type        = number
  default     = 1

  validation {
    condition     = var.daily_quota_gb == -1 || var.daily_quota_gb >= 0.023
    error_message = "daily_quota_gb must be -1 (unlimited) or at least 0.023."
  }
}

variable "tags" {
  description = "Extra tags merged onto every taggable resource."
  type        = map(string)
  default     = {}
}

# ---- Feature gates: everything is OFF by default (all of these can bill) ----

variable "enable_log_analytics_workspace" {
  description = "Create the resource group and Log Analytics workspace (billed per GB ingested)."
  type        = bool
  default     = false
}

variable "enable_sentinel" {
  description = "Onboard Microsoft Sentinel to the workspace (adds a per-GB Sentinel charge). Requires enable_log_analytics_workspace."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_sentinel || var.enable_log_analytics_workspace
    error_message = "enable_sentinel requires enable_log_analytics_workspace = true."
  }
}

variable "enable_defender_plans" {
  description = "Turn on the paid Defender for Cloud plans listed in defender_plans (Standard tier)."
  type        = bool
  default     = false
}

variable "defender_plans" {
  description = "Defender for Cloud plan names (azurerm_security_center_subscription_pricing resource_type) to enable as Standard. Defaults to the usage-priced, lowest-cost plans."
  type        = set(string)
  default     = ["Arm", "KeyVaults"]

  validation {
    condition = alltrue([for p in var.defender_plans : contains([
      "Api", "AppServices", "Arm", "CloudPosture", "Containers", "CosmosDbs", "KeyVaults",
      "OpenSourceRelationalDatabases", "SqlServers", "SqlServerVirtualMachines", "StorageAccounts", "VirtualMachines",
    ], p)])
    error_message = "Unknown Defender plan name. See README for the supported list."
  }
}

variable "enable_activity_log_diagnostics" {
  description = "Send the subscription Activity Log to the workspace via a diagnostic setting (ingestion is billed). Requires enable_log_analytics_workspace."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_activity_log_diagnostics || var.enable_log_analytics_workspace
    error_message = "enable_activity_log_diagnostics requires enable_log_analytics_workspace = true."
  }
}
