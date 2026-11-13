# gcp-security

Code-only GCP security module for AEGIS-X. **Not applied, not planned.** No GCP project or credentials exist yet, so `terraform plan` cannot run against a real project; only `fmt`, `init -backend=false` and `validate` (plus Checkov) have been run. Treat every resource below as untested against the live API until a project and credentials exist.

Everything is gated by an `enable_*` variable that defaults to `false`; with defaults the module creates nothing.

| Gate | Creates |
|---|---|
| `enable_scc_notifications` | CMEK Pub/Sub topic + `google_scc_v2_organization_notification_config` |
| `enable_audit_log_sink` | Cloud Audit Logs sink (project or org scope) to a CMEK bucket (uniform access, public access prevention, versioning, retention unlocked) |
| `enable_org_policies` | Boolean org-policy constraints from `org_policy_constraints` |

A Cloud KMS key ring/key (90-day rotation, `prevent_destroy`) is created when either of the first two gates is on and `kms_key_id` is empty.

## Prerequisites (not managed here)
APIs enabled on `project_id`: `securitycenter`, `pubsub`, `logging`, `cloudkms`, `storage`, `orgpolicy`, `cloudresourcemanager`. Caller roles: `roles/securitycenter.admin` (org), `roles/pubsub.admin` / `roles/resourcemanager.projectIamAdmin` on the topic project, `roles/logging.admin`, `roles/cloudkms.admin`, `roles/orgpolicy.policyAdmin`.

SCC creates `service-org-<ORG_ID>@gcp-sa-scc-notification.iam.gserviceaccount.com` on the first NotificationConfig and grants it `securitycenter.notificationServiceAgent` on the topic automatically, so no publisher binding is declared. If the topic sits in a VPC Service Controls perimeter, that agent needs an ingress rule.

Cloud Audit Logs: Admin Activity logs are always on. Data Access logs are not enabled by this module (they are billable); the sink filter only captures what is already produced.

## Tiers and licensing (read from Google docs, Nov 2026)
Source: <https://docs.cloud.google.com/security-command-center/docs/service-tiers> (no page date shown).

- **Standard**: no additional charge, org-level activation; posture basics, Sensitive Actions Service. **Event Threat Detection: not available.** Pub/Sub continuous exports/notifications: available.
- **Premium**: everything in Standard plus attack paths, threat detection (**Event Threat Detection available**) and compliance monitoring; Google Cloud only; project or org activation; pay-as-you-go or subscription. Cloud Logging continuous export needs org-level activation.
- **Enterprise**: multi-cloud, org-level only. The docs mark it **deprecated, shutting down 2027-05-21**, with orgs moving to Premium on/after that date. Do not build on it.

Consequence: with Standard the notification stream carries posture/misconfiguration findings only; threat findings (Event Threat Detection, etc., and the MITRE fields they carry) need Premium.

## Cost estimate (assumptions, **re-check pricing before use**)
**Premium/Enterprise SCC rates could not be retrieved** (the pricing page returned no content to my fetch), so no SCC Premium figure is stated here. Get it from <https://cloud.google.com/security-command-center/pricing>.

Rough, unverified figures from general knowledge of list prices; verify each on the respective pricing page:

| Item | Assumption | Approx. monthly |
|---|---|---|
| SCC Standard | free per docs | $0 |
| SCC Premium | **unknown – check pricing page** | not estimated |
| Pub/Sub topic (findings only, a few MB/month) | within free tier (first 10 GiB/mo) | ~$0 |
| Cloud KMS software key, 1 active version | ~$0.06/key version/mo + ops | ~$0.1 |
| Log sink → GCS Standard, e.g. 50 GiB/mo retained 12 mo (~600 GiB) | ~$0.02/GiB-mo | ~$12 |
| Logging routing to GCS | no charge for routing; Data Access log volume (if enabled) is billed on the source side | variable |
| Org policy | free | $0 |

Order of magnitude with Standard tier and modest logs: **tens of dollars/month**, dominated by log storage. **Re-check pricing** before enabling anything.

## Org-policy defaults
`storage.uniformBucketLevelAccess`, `storage.publicAccessPrevention`, `compute.requireOsLogin`, `compute.disableSerialPortAccess`, `compute.skipDefaultNetworkCreation`, `sql.restrictPublicIp`. Opt-in (not default, may break existing automation): `iam.disableServiceAccountKeyCreation`. Review against existing workloads first; apply at a folder/project before the organization.

## Validation performed
- `terraform fmt -check`, `init -backend=false`, `validate` (Terraform 1.17.1, google provider ~> 7.0): pass.
- Checkov 3.4.5 on `aegis-x/terraform`: 0 failed. Skips (inline `#checkov:skip`):
  - `CKV_GCP_62` on the audit bucket: no access-log bucket is provisioned.
  - `CKV2_GCP_4` on both sinks: Bucket Lock is irreversible, so the retention policy is set but left unlocked on purpose.
- Not done: `terraform plan`/`apply`, any API call, IAM/permission verification, org-policy conflict checks.

## Usage
```bash
cp terraform.tfvars.example terraform.tfvars   # edit placeholders
terraform init -backend=false && terraform validate
```
Add a real backend only when a project exists (see `../aws-governance/backend.tf.example` for the pattern).
