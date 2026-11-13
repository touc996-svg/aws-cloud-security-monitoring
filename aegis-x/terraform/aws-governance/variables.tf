variable "aws_region" {
  description = "Region for governance controls."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment label used in tags and names."
  type        = string
  default     = "sandbox"
}

variable "enable_config" {
  description = "Create the AWS Config recorder, delivery channel, encrypted bucket and KMS key. Billable (per configuration item recorded)."
  type        = bool
  default     = false
}

variable "config_record_all_resources" {
  description = "Record all supported resource types. When false, only the types in config_resource_types are recorded to limit cost."
  type        = bool
  default     = false
}

variable "config_resource_types" {
  description = "Resource types recorded when config_record_all_resources is false."
  type        = list(string)
  default = [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::User",
    "AWS::S3::Bucket",
    "AWS::KMS::Key",
    "AWS::EC2::SecurityGroup",
    "AWS::CloudTrail::Trail",
  ]
}

variable "config_retention_days" {
  description = "Days to keep AWS Config delivery objects before expiry."
  type        = number
  default     = 365
}

variable "enable_security_hub" {
  description = "Enable Security Hub CSPM and the standards in security_hub_standards. Billable (per security check and finding ingestion). Requires AWS Config recording."
  type        = bool
  default     = false
}

variable "security_hub_standards" {
  description = "Standard ARN suffixes to subscribe to."
  type        = list(string)
  default     = ["aws-foundational-security-best-practices/v/1.0.0"]
}

variable "enable_account_s3_public_access_block" {
  description = "Manage the account-wide S3 Block Public Access setting (all four protections on). Free. Off by default so the module changes nothing until enabled."
  type        = bool
  default     = false
}
