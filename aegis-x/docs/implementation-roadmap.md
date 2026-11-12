# AEGIS-X Implementation Roadmap

## Gate 0 — Repository and toolchain
- Preserve existing AWS project and evidence.
- Create a dedicated AEGIS-X working branch locally.
- Install and verify Terraform, AWS CLI, Azure CLI, gcloud, Python, OPA/Conftest.
- Establish secret scanning, IaC scanning, code review, and cost controls.

## Gate 1 — Governance and cloud foundations
- Define account/subscription/project hierarchy and break-glass access.
- Establish MFA, federation, least privilege, privileged access workflows, and emergency access testing.
- Configure audit logging, centralized evidence storage, encryption, retention, and alerting in each cloud.
- Configure organization policies / SCPs / Azure Policy / GCP Organization Policy.

## Gate 2 — Native security posture and threat detection
- AWS: Security Hub CSPM, GuardDuty, Inspector, Macie, Config, Detective, Security Lake as justified.
- Azure: Defender for Cloud plans, Entra identity controls, Sentinel connectors and analytics.
- GCP: Security Command Center tier, Cloud Audit Logs, Event Threat Detection, Sensitive Data Protection.
- Normalize findings without discarding native identifiers or evidence.

## Gate 3 — Network, data, workload, and application security
- Network segmentation, WAF, DDoS, DNS, egress controls, private service access.
- KMS/HSM, secrets rotation, data classification, DLP, immutable backups.
- VM/container/Kubernetes/serverless runtime security.
- SAST, DAST, SCA, IaC scanning, SBOM, artifact signing, provenance, API testing.

## Gate 4 — Detection engineering and response
- Build detections mapped to MITRE ATT&CK and test them with safe simulations.
- Add correlation, triage, case management, evidence preservation, and response runbooks.
- Start with notification and ticket creation; progress to reversible containment only after tests and approvals.

## Gate 5 — NEXUS AI integration
- Read-only investigation assistant over approved, redacted security data.
- Explainable prioritization with citations to source findings.
- Strict tool allowlists, identity boundaries, prompt-injection defenses, data-loss prevention, and audit logs.
- Human approval for all impactful actions.

## Gate 6 — Resilience and assurance
- Define RTO/RPO, test restore procedures, ransomware recovery, and cross-region recovery.
- Run purple-team exercises and detection coverage tests.
- Track MTTD, MTTR, false-positive rate, control coverage, drift, and recovery test results.

## Release gates
- `terraform fmt`, `validate`, plan review, Checkov, secret scanning, and policy tests pass.
- No credentials or sensitive identifiers committed.
- Every deployed control has an owner, evidence source, cost estimate, rollback plan, and test.
- No production deployment without explicit human approval.
