locals {
  aegis_metadata = {
    project     = "AEGIS-X"
    environment = "sandbox"
    providers   = ["aws", "azurerm", "google"]
  }
}

output "aegis_metadata" {
  description = "Non-sensitive metadata for the AEGIS-X bootstrap."
  value       = local.aegis_metadata
}
