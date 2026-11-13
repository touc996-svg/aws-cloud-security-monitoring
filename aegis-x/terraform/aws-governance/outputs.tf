output "config_bucket" {
  description = "AWS Config delivery bucket, if enabled."
  value       = one(aws_s3_bucket.config[*].id)
}

output "config_recorder_name" {
  description = "AWS Config recorder name, if enabled."
  value       = one(aws_config_configuration_recorder.this[*].name)
}

output "security_hub_enabled" {
  description = "Whether Security Hub CSPM is managed by this module."
  value       = var.enable_security_hub
}
