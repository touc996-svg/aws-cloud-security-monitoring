# Account-wide S3 Block Public Access. Free of charge. Applied by hand on
# 2026-11-13 with `aws s3control put-public-access-block`; enabling this switch
# brings that setting under Terraform (the put is an upsert, so applying over the
# existing setting is safe, or import it first:
#   terraform import 'aws_s3_account_public_access_block.this[0]' <account-id>).
resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_account_s3_public_access_block ? 1 : 0

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true

  lifecycle {
    # Removing this setting by accident would expose every future bucket;
    # turning the switch off must be a deliberate, separate step.
    prevent_destroy = true
  }
}
