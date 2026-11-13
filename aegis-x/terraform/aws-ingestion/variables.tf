variable "aws_region" {
  description = "Region where findings are produced and ingested."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment label used in tags and names."
  type        = string
  default     = "sandbox"
}

variable "enable_ingestion" {
  description = "Master gate. When false (default) NO resources are created. When true, creates the EventBridge rules, Lambda, SQS DLQ, KMS key, S3 findings bucket and log group. All billable."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "aegis-x"
}

variable "enable_guardduty_rule" {
  description = "Route GuardDuty Finding events to the ingestion Lambda (only effective when enable_ingestion is true)."
  type        = bool
  default     = true
}

variable "enable_securityhub_rule" {
  description = "Route Security Hub Findings - Imported events to the ingestion Lambda (only effective when enable_ingestion is true)."
  type        = bool
  default     = true
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for the ingestion Lambda; caps cost and protects downstream from event storms."
  type        = number
  default     = 5
}

variable "lambda_memory_mb" {
  description = "Lambda memory size in MB."
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the Lambda. Must be a value CloudWatch accepts."
  type        = number
  default     = 365
}

variable "dlq_retention_seconds" {
  description = "Message retention for the dead-letter queue (max 1209600 = 14 days)."
  type        = number
  default     = 1209600
}

variable "findings_retention_days" {
  description = "Days before current findings objects expire."
  type        = number
  default     = 365
}

variable "noncurrent_retention_days" {
  description = "Days to keep noncurrent (overwritten) object versions."
  type        = number
  default     = 90
}
