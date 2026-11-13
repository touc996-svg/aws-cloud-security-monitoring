# aws-ingestion

Code-only AWS finding ingestion path for AEGIS-X. **Everything is gated by
`enable_ingestion` (default `false`)** because every resource is billable;
with defaults `terraform plan` shows no changes. Nothing here touches the
existing GuardDuty detector or the `cloud-security-monitoring-trail` trail.

```
GuardDuty Finding ──┐
                    ├─ EventBridge rules ─► Lambda (python3.12) ─► S3 findings bucket
Security Hub        │                        │   aws.lambda_handler.handler   (KMS, versioned,
Findings - Imported ┘                        └─ failures ─► SQS DLQ             public access blocked)
```

## What gets created when enabled (21 resources in the last local plan)
- 2 EventBridge rules + targets + Lambda permissions (each rule has its own toggle)
- Lambda `python3.12`, packaged by `archive_file` from `aegis-x/integrations`
  (tests and schemas excluded); reserved concurrency (default 5); async retries 2
- CloudWatch log group with `log_retention_days` (default 365), KMS-encrypted
- SQS dead-letter queue (KMS, 14-day retention), attached as the Lambda DLQ
- KMS key (rotation on) + alias
- S3 bucket: KMS default encryption, versioning, all four public-access blocks,
  TLS-only policy, lifecycle expiry
- IAM role with only: write own log streams, `s3:PutObject` on `findings/*`,
  `sqs:SendMessage` on the DLQ, `kms:GenerateDataKey`/`Decrypt` on the key

## Behavior
- One object per finding at `findings/<url-encoded finding_id>.jsonl`, a single
  JSON line. The key is deterministic, so retries and redeliveries overwrite
  (idempotent); versioning keeps history of updated findings.
- A bad event (unknown source, invalid finding, S3 error) raises, so Lambda
  retries and then the event lands in the DLQ. Nothing is swallowed.
- Security Hub events carry several ASFF findings, so the handler uses
  `securityhub_normalizer.normalize_all`. If that module were ever missing from
  the package, those events fail into the DLQ instead of breaking GuardDuty.

## Before applying
```bash
export AWS_PROFILE=aegis-admin            # SSO role, never root
aws sso login --profile aegis-admin       # if the token is expired
terraform init -backend=false             # local validation only
terraform plan -var enable_ingestion=true
```
Review the plan and the costs below; apply only with explicit approval.

## Estimated monthly cost (sandbox scale)
**Estimate only. Re-check current AWS pricing for your region before approving.**

| Resource | Pricing model | Rough monthly |
|---|---|---|
| KMS key | per key plus requests | about USD 1 |
| EventBridge | AWS service events to rules | free |
| Lambda | requests and GB-seconds | well under USD 1 (free tier covers it) |
| S3 + KMS requests | storage and PUTs (bucket key on) | pennies |
| CloudWatch Logs | ingestion and storage | pennies to about USD 1 |
| SQS DLQ | requests | free tier, pennies |
| **Total** | at a few thousand findings/month | **roughly USD 1-3** |

Cost grows with finding volume (Lambda, S3 PUTs, logs), bounded by the reserved
concurrency. Upstream GuardDuty/Security Hub charges are separate.

## Checkov skips (inline in `main.tf`, each with a reason)
S3 access logging (CKV_AWS_18), cross-region replication (CKV_AWS_144), bucket
event notifications (CKV2_AWS_62), Lambda in VPC (CKV_AWS_117), Lambda code
signing (CKV_AWS_272).

## State
Copy `backend.tf.example` to `backend.tf` after creating an encrypted state
bucket (S3 native locking via `use_lockfile`).
