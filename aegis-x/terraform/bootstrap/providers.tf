provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AEGIS-X"
      Environment = "sandbox"
      ManagedBy   = "Terraform"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
