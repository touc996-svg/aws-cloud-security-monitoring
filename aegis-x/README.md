# AEGIS-X

**Unified multi-cloud cyber defense platform** for AWS, Microsoft Azure, and Google Cloud Platform.

AEGIS-X extends the existing `aws-cloud-security-monitoring` project. It does not replace or recreate the working AWS GuardDuty → EventBridge → SNS workflow, CloudTrail audit logging, S3 log storage, or budget alerts.

## Architecture principles

- **Cloud-native controls first:** use each provider's native identity, posture, threat detection, data protection, and response services.
- **Normalize, don't flatten:** preserve provider-native evidence and identifiers while mapping common fields into an internal event schema.
- **Terraform for repeatable infrastructure:** provider-specific modules and reusable shared modules.
- **Native automation for response:** EventBridge/Lambda/Step Functions (AWS), Event Grid/Functions/Logic Apps (Azure), and Eventarc/Cloud Run/Workflows (GCP).
- **Human approval for high-impact actions:** no autonomous destructive actions or broad privilege changes.
- **Evidence and recovery by design:** immutable audit trails, tested backups, incident timelines, and documented recovery objectives.
- **Cost governance:** budgets, alerts, tagging, retention policies, and teardown plans before enabling premium services.

## Repository layout

```text
.
├── docs/                    # architecture, controls, roadmap
├── terraform/bootstrap/     # multi-cloud provider and Terraform baseline
├── modules/aws/             # AWS-native security modules (next milestones)
├── modules/azure/           # Azure-native security modules (next milestones)
├── modules/gcp/             # GCP-native security modules (next milestones)
├── policies/opa/            # policy-as-code guardrails
├── scripts/                 # local preflight and validation helpers
└── .github/workflows/       # CI validation and IaC security scanning
```

## Prerequisites

- Terraform CLI (version constraint in `terraform/bootstrap/versions.tf`)
- AWS CLI v2, Azure CLI, and Google Cloud CLI for provider authentication
- Git, Python 3.11+, and (for policy checks) OPA / Conftest
- Separate sandbox accounts/subscriptions/projects for experiments; do not begin in production

## First local validation

```bash
cd terraform/bootstrap
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

The bootstrap currently configures providers only. **It creates no cloud resources and incurs no cloud charges.** Do not run `terraform apply` until the first reviewed baseline module and account-specific variables are added.

## Authentication

Use each cloud provider's supported CLI or workload identity federation. Do not put access keys, service-principal secrets, service-account keys, or `.tfvars` containing secrets in Git. Prefer short-lived credentials and OIDC federation for CI.

## Existing AWS project

The original AWS lab remains the source of truth for its already-deployed resources. Review and import existing resources deliberately before managing them with Terraform; never create duplicate CloudTrail trails, buckets, detectors, EventBridge rules, or SNS topics by accident.
