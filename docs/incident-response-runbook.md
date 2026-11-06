# AWS Security Incident Response Runbook

## Purpose
A repeatable procedure for investigating AWS security findings.

## Detection workflow
1. GuardDuty generates a finding.
2. EventBridge matches the finding.
3. EventBridge publishes it to SNS.
4. SNS sends an email notification.
5. CloudTrail provides supporting account activity.

## Initial triage
- Record the finding ID and detection time.
- Review the finding type and severity.
- Identify the affected AWS resource and Region.
- Determine whether the finding is simulated or real.
- Preserve the finding details.

## Investigation
- Review related CloudTrail events.
- Identify the IAM principal and source IP.
- Review relevant API activity and resource changes.
- Determine whether the activity was authorized.
- Record evidence and investigation decisions.

## Containment
Based on the confirmed incident and authorized response:
- Restrict compromised credentials or IAM principals.
- Isolate affected compute resources when appropriate.
- Restrict suspicious network access.
- Preserve evidence before making changes.

## Recovery
- Remove the confirmed cause.
- Rotate potentially exposed credentials.
- Restore affected resources when necessary.
- Validate normal operation.
- Document recovery actions and outstanding risks.

## Evidence checklist
- [ ] GuardDuty finding details
- [ ] Finding ID, severity, and timestamp
- [ ] Affected AWS resource and Region
- [ ] Related CloudTrail events
- [ ] IAM principal and source IP
- [ ] EventBridge matching evidence
- [ ] SNS notification evidence
- [ ] Investigation and recovery notes

## Original lab test
The original project used GuardDuty sample findings and confirmed
that an SNS email notification was received.

This validated alert delivery. It did not demonstrate response
to a confirmed real-world security incident.
