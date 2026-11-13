data "azurerm_subscription" "current" {}

locals {
  tags = merge({
    Project     = "AEGIS-X"
    Component   = "azure-security"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }, var.tags)

  activity_log_categories = [
    "Administrative", "Security", "ServiceHealth", "Alert", "Recommendation",
    "Policy", "Autoscale", "ResourceHealth",
  ]
}

resource "azurerm_resource_group" "security" {
  count    = var.enable_log_analytics_workspace ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "security" {
  count               = var.enable_log_analytics_workspace ? 1 : 0
  name                = var.workspace_name
  location            = azurerm_resource_group.security[0].location
  resource_group_name = azurerm_resource_group.security[0].name
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_in_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  count        = var.enable_sentinel ? 1 : 0
  workspace_id = azurerm_log_analytics_workspace.security[0].id
}

resource "azurerm_security_center_subscription_pricing" "plan" {
  for_each      = var.enable_defender_plans ? var.defender_plans : toset([])
  resource_type = each.value
  tier          = "Standard"
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  count                      = var.enable_activity_log_diagnostics ? 1 : 0
  name                       = "aegisx-activity-log"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security[0].id

  dynamic "enabled_log" {
    for_each = local.activity_log_categories
    content {
      category = enabled_log.value
    }
  }
}
