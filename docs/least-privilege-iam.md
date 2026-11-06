# Least-Privilege IAM Design

## EventBridge to CloudWatch Logs

The CloudFormation template
`infrastructure/guardduty-cloudwatch.yaml` creates a resource-based
CloudWatch Logs policy.

It grants only:
- logs:CreateLogStream
- logs:PutLogEvents

The permitted principals are the EventBridge and log-delivery services.
The policy is scoped to the GuardDuty log group's streams and the
specific EventBridge rule ARN.

No administrator permissions or wildcard service permissions are granted.

## EventBridge to SNS

The original alerting workflow uses an SNS topic as its target.

The SNS topic policy should grant `sns:Publish` to
`events.amazonaws.com`, scoped to the ARN of the specific
GuardDuty EventBridge rule.

Do not grant public access or unrestricted publishing permissions.

## EC2 Systems Manager role

The original lab created an IAM role with
`AmazonSSMManagedInstanceCore`.

Keep this role attached only to EC2 instances that need Systems Manager
management. Review its trust relationship and attached policies.
Do not replace the AWS-managed policy with a smaller custom policy
without validating the Systems Manager features the instance uses.

## Credentials and deployment

- Never commit AWS access keys, secrets, or account credentials.
- Prefer IAM roles and temporary credentials.
- Review permissions before deploying changes.
- Inspect existing AWS resources to avoid duplicate trails,
  detectors, rules, and notification targets.

## Scope

These are least-privilege design controls for the lab. They have not
been deployed or independently verified in the AWS account.
