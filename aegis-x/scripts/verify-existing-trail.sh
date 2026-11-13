#!/usr/bin/env bash
# Read-only check that the original CloudTrail trail is intact.
set -Eeuo pipefail
TRAIL="${1:-cloud-security-monitoring-trail}"
REGION="${AWS_REGION:-us-east-1}"

status="$(aws cloudtrail get-trail-status --name "$TRAIL" --region "$REGION" --query IsLogging --output text)"
detail="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" \
  --query 'trailList[0].[IsMultiRegionTrail,LogFileValidationEnabled]' --output text)"

echo "Trail: $TRAIL  IsLogging=$status  MultiRegion/LogValidation=$detail"
[[ "$status" == "True" && "$detail" == $'True\tTrue' ]] || { echo "[FAIL] Trail changed or not logging"; exit 1; }
echo "[OK] Existing CloudTrail trail intact."
