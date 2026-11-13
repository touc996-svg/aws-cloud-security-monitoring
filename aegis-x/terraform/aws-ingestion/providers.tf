provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AEGIS-X"
      Component   = "aws-ingestion"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
