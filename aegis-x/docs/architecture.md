# AEGIS-X Architecture

## Control planes

1. **AWS:** Organizations / Control Tower (where available), IAM Identity Center, SCPs, CloudTrail, AWS Config, Security Hub CSPM, GuardDuty, Inspector, Macie, Detective, Security Lake, KMS, Secrets Manager, WAF, Shield, Network Firewall, Backup, EventBridge, Lambda, Step Functions.
2. **Azure:** Management Groups and Azure Policy, Microsoft Entra ID, Conditional Access and PIM, Defender for Cloud, Defender XDR where licensed, Microsoft Sentinel, Azure Activity Logs, Azure Monitor, Key Vault, Azure Firewall, Front Door WAF, DDoS Protection, Storage immutable policies, Logic Apps / Functions.
3. **GCP:** Organization / Folders / Projects, Cloud Identity and IAM, Organization Policy, Security Command Center, Cloud Audit Logs, Cloud Logging and Monitoring, Event Threat Detection, Sensitive Data Protection, Cloud KMS, Secret Manager, Cloud Armor, VPC Service Controls, Cloud Backup and DR, Eventarc / Cloud Run / Workflows.

Service availability, licensing, regions, and product packaging vary. Select tiers only after confirming requirements and pricing for the target tenant.

## Shared platform

- **Collection:** provider-native findings, audit logs, identity events, network telemetry, workload findings, CI/CD and application security results.
- **Normalization:** map to a versioned AEGIS-X event envelope while retaining original provider payloads and immutable source references.
- **Correlation:** identity + resource + network + vulnerability + threat context; map observed behaviors to MITRE ATT&CK.
- **Analytics:** central search and dashboards, risk scoring with explainable contributing factors, alert deduplication and suppression.
- **Response:** provider-native automation adapters, ticketing/notification integrations, approval gates, idempotency, rollback/compensation, and full action audit.
- **AI/NEXUS:** read-only investigation and summarization initially; narrowly scoped tool permissions, explicit policy checks, human approval for containment, and no direct access to cloud credentials.

## Security boundaries

- Separate management, security/log archive, shared services, and workload environments.
- Use dedicated sandbox accounts/subscriptions/projects for experiments.
- Prefer private endpoints, segmented networks, default-deny egress where practical, and short-lived workload identity.
- Centralize logs into separately administered storage with encryption, retention locks where legally appropriate, and tested access controls.
- Keep provider-native security findings available even if the central analytics platform is unavailable.

## Deployment model

Terraform provisions repeatable baseline resources and integrations. Native cloud services perform event-driven operations. Provider modules are isolated so a provider-specific failure or change does not block the other clouds. Terraform state must use encrypted remote storage, locking, restricted access, and separate state per environment/provider; the local backend is for initial validation only.
