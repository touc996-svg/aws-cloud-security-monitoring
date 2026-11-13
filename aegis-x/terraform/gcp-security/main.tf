data "google_project" "this" {
  count      = (var.enable_scc_notifications || var.enable_audit_log_sink) ? 1 : 0
  project_id = var.project_id
}

locals {
  create_key  = (var.enable_scc_notifications || var.enable_audit_log_sink) && var.kms_key_id == ""
  need_key    = var.enable_scc_notifications || var.enable_audit_log_sink
  kms_key     = local.create_key ? google_kms_crypto_key.this[0].id : var.kms_key_id
  project_num = local.need_key ? data.google_project.this[0].number : ""
  org_scope   = var.audit_sink_scope == "organization"
}

check "organization_id_set" {
  assert {
    condition     = !(var.enable_scc_notifications || (var.enable_audit_log_sink && local.org_scope)) || var.organization_id != ""
    error_message = "organization_id is required for SCC notifications and the organization-level sink."
  }
}

check "org_policy_parent_set" {
  assert {
    condition     = !var.enable_org_policies || var.org_policy_parent != ""
    error_message = "org_policy_parent is required when enable_org_policies = true."
  }
}

# ---------------- Cloud KMS (CMEK) ----------------

resource "google_kms_key_ring" "this" {
  count    = local.create_key ? 1 : 0
  name     = "${var.name_prefix}-security"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "this" {
  count           = local.create_key ? 1 : 0
  name            = "${var.name_prefix}-security-key"
  key_ring        = google_kms_key_ring.this[0].id
  rotation_period = var.kms_key_rotation_period
  labels          = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

# Storage and Pub/Sub service agents need the key.
resource "google_kms_crypto_key_iam_member" "gcs" {
  count         = var.enable_audit_log_sink ? 1 : 0
  crypto_key_id = local.kms_key
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${local.project_num}@gs-project-accounts.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "pubsub" {
  count         = var.enable_scc_notifications ? 1 : 0
  crypto_key_id = local.kms_key
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${local.project_num}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# ---------------- SCC -> Pub/Sub ----------------

resource "google_pubsub_topic" "scc" {
  count                      = var.enable_scc_notifications ? 1 : 0
  name                       = "${var.name_prefix}-scc-findings"
  project                    = var.project_id
  kms_key_name               = local.kms_key
  message_retention_duration = var.pubsub_message_retention
  labels                     = var.labels

  depends_on = [google_kms_crypto_key_iam_member.pubsub]
}

# SCC automatically grants its notification service agent publish rights on the
# topic when the config is created (see README); no manual IAM binding here.
resource "google_scc_v2_organization_notification_config" "this" {
  count        = var.enable_scc_notifications ? 1 : 0
  config_id    = "${var.name_prefix}-findings"
  organization = var.organization_id
  location     = "global"
  description  = "AEGIS-X: stream SCC findings to Pub/Sub"
  pubsub_topic = google_pubsub_topic.scc[0].id

  streaming_config {
    filter = var.scc_notification_filter
  }
}

# ---------------- Cloud Audit Logs -> encrypted bucket ----------------

resource "google_storage_bucket" "audit" {
  #checkov:skip=CKV_GCP_62:Access-log bucket not provisioned; Cloud Audit Logs on the project cover bucket admin activity. Revisit if a central access-log bucket exists.
  count                       = var.enable_audit_log_sink ? 1 : 0
  name                        = "${var.name_prefix}-audit-logs-${var.project_id}"
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = var.labels

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = local.kms_key
  }

  retention_policy {
    retention_period = var.log_retention_days * 86400
    is_locked        = false
  }

  lifecycle_rule {
    condition {
      age = var.log_retention_days + 30
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs]
}

resource "google_logging_organization_sink" "audit" {
  #checkov:skip=CKV2_GCP_4:Bucket Lock is irreversible; retention_policy is set but intentionally unlocked (is_locked=false). Lock manually after validating retention.
  count            = var.enable_audit_log_sink && local.org_scope ? 1 : 0
  name             = "${var.name_prefix}-audit-sink"
  org_id           = var.organization_id
  destination      = "storage.googleapis.com/${google_storage_bucket.audit[0].name}"
  filter           = var.audit_log_filter
  include_children = true
}

resource "google_logging_project_sink" "audit" {
  #checkov:skip=CKV2_GCP_4:Bucket Lock is irreversible; retention_policy is set but intentionally unlocked (is_locked=false). Lock manually after validating retention.
  count                  = var.enable_audit_log_sink && !local.org_scope ? 1 : 0
  name                   = "${var.name_prefix}-audit-sink"
  project                = var.project_id
  destination            = "storage.googleapis.com/${google_storage_bucket.audit[0].name}"
  filter                 = var.audit_log_filter
  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  count  = var.enable_audit_log_sink ? 1 : 0
  bucket = google_storage_bucket.audit[0].name
  role   = "roles/storage.objectCreator"
  member = local.org_scope ? google_logging_organization_sink.audit[0].writer_identity : google_logging_project_sink.audit[0].writer_identity
}

# ---------------- Org policy ----------------

resource "google_org_policy_policy" "boolean" {
  for_each = var.enable_org_policies ? toset(var.org_policy_constraints) : toset([])
  name     = "${var.org_policy_parent}/policies/${trimprefix(each.value, "constraints/")}"
  parent   = var.org_policy_parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}
