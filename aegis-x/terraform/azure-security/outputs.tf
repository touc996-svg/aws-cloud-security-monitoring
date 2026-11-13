output "workspace_id" {
  description = "Log Analytics workspace resource ID (null when not enabled)."
  value       = one(azurerm_log_analytics_workspace.security[*].id)
}

output "enabled_defender_plans" {
  description = "Defender for Cloud plans set to Standard by this module."
  value       = sort(keys(azurerm_security_center_subscription_pricing.plan))
}
