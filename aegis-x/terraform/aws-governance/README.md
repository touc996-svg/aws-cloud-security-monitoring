# aws-governance

AWS Config and Security Hub CSPM for the AEGIS-X sandbox account. **Both are
off by default** because they are billable. Nothing here creates, edits or
replaces the existing GuardDuty detector or the `cloud-security-monitoring-trail`
CloudTrail trail.

## Account-wide S3 Block Public Access
`enable_account_s3_public_access_block` (free, default `false`) manages the
account-level setting. It was first applied by CLI on 2026-11-13 after confirming
the only buckets (two CloudTrail log buckets) were private. The Terraform
resource is an upsert, so enabling it over the live setting is safe; it has
`prevent_destroy` so it cannot be removed by accident. Use shared remote state
(see below) before relying on it, otherwise state lives only on one laptop.

## Why there is no organization trail
The Organization currently has a single account. The existing trail is already
multi-region, KMS-encrypted and log-validated. A second (organization) trail
would only duplicate the same management events and be billed as an additional
trail. Revisit when member accounts are added.

## Before applying
```bash
export AWS_PROFILE=aegis-admin            # SSO role, never root
../../scripts/verify-existing-trail.sh     # read-only trail check
terraform init -backend=false              # local validation only
terraform plan -var enable_config=true -var enable_security_hub=true
```
Review the plan (16 resources to add, 0 change, 0 destroy at the time of
writing) and the costs below, then apply only with explicit approval.

## Approximate cost (verify against current AWS pricing before approving)
| Control | Pricing model | Expectation for this account |
|---|---|---|
| AWS Config | per configuration item recorded | Small: scoped to 7 security resource types |
| Security Hub CSPM | per security check and per ingested finding; free trial for new accounts | Small at sandbox scale after the trial |
| KMS key | about USD 1 per month plus requests | About USD 1 per month |
| S3 (Config bucket) | storage and requests | Pennies |

Security Hub's foundational standard assumes Config records all resources.
With scoped recording, some controls will report no data or false results. Set
`config_record_all_resources=true` for accurate scoring, which raises Config cost.

## State
Local validation uses `-backend=false`. For shared use, copy
`backend.tf.example` to `backend.tf` after creating an encrypted state bucket
(S3 native locking via `use_lockfile`).
