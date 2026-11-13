#!/usr/bin/env bash
# Read-only live check of the AEGIS-X AWS security posture.
# Never creates or changes anything. Run with an SSO profile, never root:
#   AWS_PROFILE=aegis-admin aegis-x/scripts/verify-controls.sh
# Exit code: 0 = no FAIL, 1 = at least one FAIL. WARN and INFO never fail the run.
set -uo pipefail

REGION="${AWS_REGION:-us-east-1}"
TRAIL="${TRAIL_NAME:-cloud-security-monitoring-trail}"
FAILS=0

pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAILS=$((FAILS + 1)); }
warn() { printf '[WARN] %s\n' "$1"; }
info() { printf '[INFO] %s\n' "$1"; }
q()    { aws "$@" --region "$REGION" --output text 2>/dev/null; }

caller_arn="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
if [[ -z "$caller_arn" ]]; then
  echo "[FAIL] cannot call AWS (expired SSO session? run: aws sso login --profile aegis-admin)"; exit 1
fi
account="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$caller_arn" == *":root" ]]; then fail "running as root ($caller_arn); use the SSO profile"; else pass "not root: ${caller_arn##*/}"; fi

# Root account hygiene
mfa="$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null || echo unknown)"
[[ "$mfa" == "1" ]] && pass "root MFA enabled" || fail "root MFA not enabled (AccountMFAEnabled=$mfa)"
keys="$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null || echo unknown)"
[[ "$keys" == "0" ]] && pass "no root access keys" || fail "root access keys present (AccountAccessKeysPresent=$keys)"

# Identity Center
ic_status="$(q sso-admin list-instances --query 'Instances[0].Status')"
[[ "$ic_status" == "ACTIVE" ]] && pass "IAM Identity Center instance ACTIVE" || fail "IAM Identity Center not active (status=${ic_status:-none})"

# CloudTrail (the original trail must stay intact)
logging="$(q cloudtrail get-trail-status --name "$TRAIL" --query IsLogging)"
detail="$(q cloudtrail describe-trails --trail-name-list "$TRAIL" --query 'trailList[0].[IsMultiRegionTrail,LogFileValidationEnabled,KmsKeyId]')"
[[ "$logging" == "True" ]] && pass "trail $TRAIL is logging" || fail "trail $TRAIL not logging"
[[ "$detail" == True$'\t'True$'\t'* ]] && pass "trail is multi-region with log file validation" || fail "trail multi-region/log-validation changed: $detail"
[[ "$detail" == *arn:aws:kms* ]] && pass "trail logs are KMS-encrypted" || warn "trail logs not KMS-encrypted"
bucket="$(q cloudtrail describe-trails --trail-name-list "$TRAIL" --query 'trailList[0].S3BucketName')"
if [[ -n "$bucket" && "$bucket" != "None" ]]; then
  pab="$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,BlockPublicPolicy,IgnorePublicAcls,RestrictPublicBuckets]' --output text 2>/dev/null || echo missing)"
  [[ "$pab" == True$'\t'True$'\t'True$'\t'True ]] && pass "trail bucket blocks all public access" || fail "trail bucket public access block incomplete: $pab"
fi

# Detection
det="$(q guardduty list-detectors --query 'DetectorIds[0]')"
if [[ -n "$det" && "$det" != "None" ]]; then
  st="$(q guardduty get-detector --detector-id "$det" --query Status)"
  [[ "$st" == "ENABLED" ]] && pass "GuardDuty detector ENABLED" || fail "GuardDuty detector status=$st"
else
  fail "no GuardDuty detector"
fi

# Account-level S3 protection
acct_pab="$(aws s3control get-public-access-block --account-id "$account" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,BlockPublicPolicy,IgnorePublicAcls,RestrictPublicBuckets]' --output text 2>/dev/null || echo missing)"
[[ "$acct_pab" == True$'\t'True$'\t'True$'\t'True ]] && pass "account-level S3 public access block on" || warn "account-level S3 public access block not fully on ($acct_pab)"

# Governance controls (off by default in code; reported, not failed)
cfg="$(q configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[0].recording')"
[[ "$cfg" == "True" ]] && pass "AWS Config recording" || info "AWS Config not recording (aws-governance enable_config is off)"
if aws securityhub describe-hub --region "$REGION" >/dev/null 2>&1; then pass "Security Hub enabled"; else info "Security Hub not enabled (enable_security_hub is off)"; fi
if aws lambda get-function --function-name aegis-x-ingestion --region "$REGION" >/dev/null 2>&1; then pass "ingestion Lambda deployed"; else info "ingestion Lambda not deployed (enable_ingestion is off)"; fi

echo
if (( FAILS > 0 )); then echo "RESULT: $FAILS check(s) FAILED"; exit 1; fi
echo "RESULT: no failures"
