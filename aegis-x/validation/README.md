# AEGIS-X validation (workstream 7)

Automated, offline tests. They need no cloud access and create nothing.

```bash
cd aegis-x
pip install -r validation/requirements.txt
python -m pytest -q validation
```

| File | What it proves |
|---|---|
| `test_end_to_end_flow.py` | Real fixtures from GuardDuty, Security Hub, Sentinel, Defender and SCC go through the real normalizers and pipeline: schema-valid, raw payload kept, GuardDuty/Security Hub duplicates collapsed, bad input quarantined, byte-identical output across runs |
| `test_recovery.py` | Redelivery and DLQ replay never duplicate findings; one failed write never blocks the others; derived state can be rebuilt from the object store with identical results |
| `test_terraform_governance.py` | Billable switches default off, gated resources honour them, S3 buckets private + KMS + versioned, KMS rotation, no wildcard IAM (except the account-root key-admin statement), no hard-coded account ids or credentials |
| `test_security_controls.py` | Normalizers and the pipeline import no network or cloud SDKs, the Lambda imports boto3 lazily and has no destructive calls, no secrets or state files are tracked |

## Known behaviour (documented, not a defect)
- Replaying an event rewrites the object with a refreshed `ingested_at`; the key and every other field are unchanged.
- Pipeline output records the source file path, so rebuilt output is identical only when read from the same path.

## Live, read-only account check
`aegis-x/scripts/verify-controls.sh` (needs `AWS_PROFILE=aegis-admin`, never root) reports PASS/FAIL/WARN/INFO for root MFA and keys, Identity Center, the existing trail, GuardDuty and account-level S3 protection. It changes nothing.

## Not covered
Incident *response execution* does not exist yet (by design: NEXUS is read-only), so there is nothing to test for approvals, rollback or audit trails. Deployed behaviour (Lambda, EventBridge, DLQ) is untested until `enable_ingestion` is applied with approval.
