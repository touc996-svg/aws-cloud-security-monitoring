# AWS finding ingestion: EventBridge -> Lambda -> KMS-encrypted S3 (JSON Lines),
# with an SQS dead-letter queue. Everything is gated by var.enable_ingestion
# (default false) because every resource here is billable.

locals {
  enabled       = var.enable_ingestion
  function_name = "${var.name_prefix}-${var.environment}-finding-ingest"
  bucket_name   = local.enabled ? "${var.name_prefix}-${var.environment}-findings-${data.aws_caller_identity.current[0].account_id}-${var.aws_region}" : ""
  log_group     = "/aws/lambda/${local.function_name}"
}

data "aws_caller_identity" "current" {
  count = local.enabled ? 1 : 0
}

data "aws_partition" "current" {
  count = local.enabled ? 1 : 0
}

# --- KMS ---------------------------------------------------------------------

data "aws_iam_policy_document" "kms" {
  count = local.enabled ? 1 : 0

  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current[0].partition}:iam::${data.aws_caller_identity.current[0].account_id}:root"]
    }
  }

  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current[0].partition}:logs:${var.aws_region}:${data.aws_caller_identity.current[0].account_id}:log-group:${local.log_group}"]
    }
  }
}

resource "aws_kms_key" "ingestion" {
  count = local.enabled ? 1 : 0

  description             = "AEGIS-X finding ingestion (S3, SQS DLQ, logs, Lambda env)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms[0].json
}

resource "aws_kms_alias" "ingestion" {
  count = local.enabled ? 1 : 0

  name          = "alias/${var.name_prefix}-${var.environment}-ingestion"
  target_key_id = aws_kms_key.ingestion[0].key_id
}

# --- S3 findings bucket --------------------------------------------------------

# checkov:skip=CKV_AWS_18: Access logging needs a separate log bucket (itself billable, unlogged); object-level writes are already recorded by CloudTrail data events if enabled.
resource "aws_s3_bucket" "findings" {
  # checkov:skip=CKV_AWS_18: Access logging needs a separate log bucket (itself billable and unlogged); out of scope for this sandbox module.
  # checkov:skip=CKV_AWS_144: Cross-region replication is out of scope for a single-region sandbox; revisit for production DR.
  # checkov:skip=CKV2_AWS_62: No consumer of bucket events exists yet; the downstream pipeline reads the bucket directly.
  count = local.enabled ? 1 : 0

  bucket = local.bucket_name
}

resource "aws_s3_bucket_ownership_controls" "findings" {
  count = local.enabled ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  count = local.enabled ? 1 : 0

  bucket                  = aws_s3_bucket.findings[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "findings" {
  count = local.enabled ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  count = local.enabled ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ingestion[0].arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  count = local.enabled ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id

  rule {
    id     = "expire-findings"
    status = "Enabled"
    filter {}

    expiration {
      days = var.findings_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.findings]
}

data "aws_iam_policy_document" "bucket" {
  count = local.enabled ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.findings[0].arn, "${aws_s3_bucket.findings[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "findings" {
  count = local.enabled ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id
  policy = data.aws_iam_policy_document.bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.findings]
}

# --- SQS dead-letter queue -------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  count = local.enabled ? 1 : 0

  name                      = "${local.function_name}-dlq"
  message_retention_seconds = var.dlq_retention_seconds
  kms_master_key_id         = aws_kms_key.ingestion[0].arn
}

# --- Lambda ----------------------------------------------------------------------

# Package the integrations tree (handler + normalizers) without tests/schemas.
data "archive_file" "lambda" {
  count = local.enabled ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/../../integrations"
  output_path = "${path.module}/.build/finding-ingest.zip"
  excludes = [
    "tests",
    "schemas",
    "requirements-dev.txt",
    "__pycache__",
    "aws/__pycache__",
    ".pytest_cache",
  ]
}

resource "aws_cloudwatch_log_group" "lambda" {
  count = local.enabled ? 1 : 0

  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.ingestion[0].arn
}

data "aws_iam_policy_document" "lambda_assume" {
  count = local.enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda" {
  count = local.enabled ? 1 : 0

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda[0].arn}:*"]
  }

  statement {
    sid       = "WriteFindings"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.findings[0].arn}/findings/*"]
  }

  statement {
    sid       = "SendToDlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq[0].arn]
  }

  statement {
    sid       = "UseKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.ingestion[0].arn]
  }
}

resource "aws_iam_role" "lambda" {
  count = local.enabled ? 1 : 0

  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume[0].json
}

resource "aws_iam_role_policy" "lambda" {
  count = local.enabled ? 1 : 0

  name   = "least-privilege"
  role   = aws_iam_role.lambda[0].id
  policy = data.aws_iam_policy_document.lambda[0].json
}

# checkov:skip=CKV_AWS_117: The function calls only regional AWS APIs (S3, SQS); a VPC would add NAT/endpoint cost for no isolation benefit.
# checkov:skip=CKV_AWS_272: Code signing needs a signing profile (extra service); the package is built from this repo by Terraform.
resource "aws_lambda_function" "ingest" {
  # checkov:skip=CKV_AWS_117: Function only calls regional AWS APIs (S3, SQS); a VPC would add NAT/endpoint cost for no isolation benefit.
  # checkov:skip=CKV_AWS_272: Code signing needs a signing profile; the package is built from this repo by Terraform.
  count = local.enabled ? 1 : 0

  function_name                  = local.function_name
  role                           = aws_iam_role.lambda[0].arn
  runtime                        = "python3.12"
  handler                        = "aws.lambda_handler.handler"
  filename                       = data.archive_file.lambda[0].output_path
  source_code_hash               = data.archive_file.lambda[0].output_base64sha256
  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_seconds
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  kms_key_arn                    = aws_kms_key.ingestion[0].arn

  environment {
    variables = {
      FINDINGS_BUCKET = aws_s3_bucket.findings[0].id
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq[0].arn
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

resource "aws_lambda_function_event_invoke_config" "ingest" {
  count = local.enabled ? 1 : 0

  function_name                = aws_lambda_function.ingest[0].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}

# --- EventBridge -----------------------------------------------------------------

locals {
  rules = {
    guardduty = {
      enabled     = var.enable_guardduty_rule
      source      = "aws.guardduty"
      detail_type = "GuardDuty Finding"
    }
    securityhub = {
      enabled     = var.enable_securityhub_rule
      source      = "aws.securityhub"
      detail_type = "Security Hub Findings - Imported"
    }
  }
  active_rules = { for k, v in local.rules : k => v if local.enabled && v.enabled }
}

resource "aws_cloudwatch_event_rule" "findings" {
  for_each = local.active_rules

  name        = "${local.function_name}-${each.key}"
  description = "Route ${each.value.detail_type} events to the AEGIS-X ingestion Lambda"
  event_pattern = jsonencode({
    source        = [each.value.source]
    "detail-type" = [each.value.detail_type]
  })
}

resource "aws_cloudwatch_event_target" "findings" {
  for_each = local.active_rules

  rule = aws_cloudwatch_event_rule.findings[each.key].name
  arn  = aws_lambda_function.ingest[0].arn
}

resource "aws_lambda_permission" "events" {
  for_each = local.active_rules

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings[each.key].arn
}
