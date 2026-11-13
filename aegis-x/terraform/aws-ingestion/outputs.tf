output "findings_bucket" {
  description = "S3 bucket receiving normalized JSON Lines findings, if enabled."
  value       = one(aws_s3_bucket.findings[*].id)
}

output "lambda_function_name" {
  description = "Ingestion Lambda name, if enabled."
  value       = one(aws_lambda_function.ingest[*].function_name)
}

output "dlq_url" {
  description = "Dead-letter queue URL, if enabled."
  value       = one(aws_sqs_queue.dlq[*].url)
}

output "kms_key_arn" {
  description = "KMS key protecting the bucket, queue and log group, if enabled."
  value       = one(aws_kms_key.ingestion[*].arn)
}
