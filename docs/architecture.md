# AWS Security Monitoring Architecture

```mermaid
flowchart TD
    A[AWS Account Activity] --> B[CloudTrail]
    B --> C[(S3 Audit Log Bucket)]

    D[GuardDuty] --> E[EventBridge]
    E --> F[SNS Topic]
    F --> G[Email Alert]

    E --> H[CloudWatch Logs]
    H --> I[Metric Filters]
    I --> J[CloudWatch Dashboard]

    K[AWS Budgets] --> L[Cost Notifications]
