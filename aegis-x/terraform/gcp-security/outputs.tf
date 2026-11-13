output "scc_topic_id" {
  description = "Pub/Sub topic receiving SCC findings (null when disabled)."
  value       = try(google_pubsub_topic.scc[0].id, null)
}

output "audit_log_bucket" {
  description = "Audit log bucket name (null when disabled)."
  value       = try(google_storage_bucket.audit[0].name, null)
}

output "kms_key_id" {
  description = "CMEK key used by the bucket and topic (null when nothing is enabled)."
  value       = (var.enable_scc_notifications || var.enable_audit_log_sink) ? local.kms_key : null
}
