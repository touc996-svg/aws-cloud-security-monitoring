provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AEGIS-X"
      Component   = "aws-governance"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
