variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID supplied through environment or tfvars"
  type        = string
  default     = null
  sensitive   = true
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = null
}

variable "gcp_region" {
  description = "GCP deployment region"
  type        = string
  default     = "us-east1"
}
