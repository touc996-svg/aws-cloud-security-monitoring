data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# This module never creates or modifies CloudTrail. The original trail from the
# AWS security monitoring project is preserved; verify it with
# scripts/verify-existing-trail.sh before applying anything.
