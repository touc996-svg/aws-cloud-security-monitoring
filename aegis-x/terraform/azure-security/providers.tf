# azurerm 4.x requires an explicit subscription. Supply it via tfvars or the
# ARM_SUBSCRIPTION_ID environment variable; never commit credentials.
provider "azurerm" {
  subscription_id = var.subscription_id

  # Do not auto-register resource providers: registration is a tenant/subscription
  # change that should be made deliberately (see README prerequisites).
  resource_provider_registrations = "none"

  features {}
}
