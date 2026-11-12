#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGION="us-east-1"

cd "$ROOT"

section() {
  printf "\n========================================\n"
  printf " %s\n" "$1"
  printf "========================================\n"
}

check() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "[OK] $1 installed"
  else
    echo "[MISSING] $1"
  fi
}

section "AEGIS-X PLATFORM BUILD"

check aws
check terraform
check az
check gcloud
check python3
check git

section "1. AWS IDENTITY CENTER"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
echo "AWS account: $ACCOUNT_ID"

INSTANCE_ARN="$(aws sso-admin list-instances \
  --region "$REGION" \
  --query 'Instances[0].InstanceArn' --output text)"

STORE_ID="$(aws sso-admin list-instances \
  --region "$REGION" \
  --query 'Instances[0].IdentityStoreId' --output text)"

if [[ "$INSTANCE_ARN" == "None" || "$STORE_ID" == "None" ]]; then
  echo "[STOP] IAM Identity Center instance not found."
  exit 1
fi

echo "Identity Center: $INSTANCE_ARN"
echo "Identity Store: $STORE_ID"

read -r -p "Administrator email: " EMAIL
read -r -p "Given name: " GIVEN
read -r -p "Family name: " FAMILY

if [[ -z "$EMAIL" || -z "$GIVEN" || -z "$FAMILY" ]]; then
  echo "[STOP] Email and name are required."
  exit 1
fi

USER_ID="$(aws identitystore list-users \
  --identity-store-id "$STORE_ID" \
  --query "Users[?UserName=='$EMAIL'].UserId | [0]" \
  --output text)"

if [[ "$USER_ID" == "None" ]]; then
  echo "Creating Identity Center user..."
  USER_ID="$(aws identitystore create-user \
    --identity-store-id "$STORE_ID" \
    --user-name "$EMAIL" \
    --display-name "$GIVEN $FAMILY" \
    --name "{\"GivenName\":\"$GIVEN\",\"FamilyName\":\"$FAMILY\"}" \
    --emails "[{\"Value\":\"$EMAIL\",\"Type\":\"work\",\"Primary\":true}]" \
    --query UserId --output text)"
else
  echo "Identity Center user already exists."
fi

echo "User ID: $USER_ID"

echo
echo "This permission set grants AdministratorAccess to the AWS management account."
read -r -p "Type CREATE-ADMIN to authorize this assignment: " APPROVAL

if [[ "$APPROVAL" == "CREATE-ADMIN" ]]; then
  PS_ARN="$(aws sso-admin list-permission-sets \
    --instance-arn "$INSTANCE_ARN" \
    --region "$REGION" \
    --query "PermissionSets" --output text | tr '\t' '\n' |
    while read -r ARN; do
      NAME="$(aws sso-admin describe-permission-set \
        --instance-arn "$INSTANCE_ARN" \
        --permission-set-arn "$ARN" \
        --region "$REGION" \
        --query 'PermissionSet.Name' --output text)"
      if [[ "$NAME" == "AegisX-BootstrapAdmin" ]]; then
        echo "$ARN"
        break
      fi
    done)"

  if [[ -z "$PS_ARN" ]]; then
    PS_ARN="$(aws sso-admin create-permission-set \
      --instance-arn "$INSTANCE_ARN" \
      --name "AegisX-BootstrapAdmin" \
      --description "Temporary bootstrap administrator for AEGIS-X" \
      --session-duration "PT1H" \
      --region "$REGION" \
      --query 'PermissionSet.PermissionSetArn' --output text)"
  fi

  aws sso-admin attach-managed-policy-to-permission-set \
    --instance-arn "$INSTANCE_ARN" \
    --permission-set-arn "$PS_ARN" \
    --managed-policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" \
    --region "$REGION" 2>&1 | grep -v ConflictException || true

  aws sso-admin provision-permission-set \
    --instance-arn "$INSTANCE_ARN" \
    --permission-set-arn "$PS_ARN" \
    --target-type AWS_ACCOUNT \
    --target-id "$ACCOUNT_ID" \
    --region "$REGION" >/dev/null

  aws sso-admin create-account-assignment \
    --instance-arn "$INSTANCE_ARN" \
    --target-id "$ACCOUNT_ID" \
    --target-type AWS_ACCOUNT \
    --permission-set-arn "$PS_ARN" \
    --principal-type USER \
    --principal-id "$USER_ID" \
    --region "$REGION"

  echo "[REQUESTED] Administrator permission assignment."
else
  echo "[SKIPPED] Administrator permission assignment."
fi

section "2. AWS ORGANIZATION GOVERNANCE"

aws organizations describe-organization \
  --query 'Organization.{Id:Id,Features:FeatureSet,ManagementAccount:MasterAccountId}' \
  --output table

section "3. AWS SECURITY SERVICES"

for SERVICE in guardduty securityhub config; do
  echo "Checking $SERVICE..."
done

aws guardduty list-detectors --region "$REGION" --output table
aws securityhub describe-hub --region "$REGION" \
  --query '{HubArn:HubArn,SubscribedAt:SubscribedAt}' \
  --output table 2>/dev/null || echo "[INFO] Security Hub not enabled."
aws configservice describe-configuration-recorders \
  --region "$REGION" --output table

section "4. AZURE ENVIRONMENT"

if command -v az >/dev/null 2>&1; then
  az account show --query '{Subscription:id,Name:name,Tenant:tenantId}' \
    --output table 2>/dev/null || echo "[NOT CONNECTED] Run az login when ready."
else
  echo "[NOT INSTALLED] Azure CLI"
fi

section "5. GOOGLE CLOUD ENVIRONMENT"

if command -v gcloud >/dev/null 2>&1; then
  gcloud auth list 2>/dev/null || true
  gcloud config get-value project 2>/dev/null || true
else
  echo "[NOT INSTALLED] Google Cloud CLI"
fi

section "6. CROSS-CLOUD FINDING SCHEMA"

SCHEMA="aegis-x/integrations/schemas/finding.schema.json"

if [[ ! -f "$SCHEMA" ]]; then
  echo "[STOP] Missing $SCHEMA"
  exit 1
fi

python3 -m json.tool "$SCHEMA" >/dev/null
echo "[OK] Cross-cloud finding schema validated."

section "7. NEXUS AI INTEGRATION"

NEXUS="$HOME/Projects/nexus-ai"

if [[ -f "$NEXUS/main.py" ]]; then
  echo "[FOUND] NEXUS AI repository: $NEXUS"
else
  echo "[CHECK] NEXUS repository or main.py not found at expected path."
fi

section "8. TERRAFORM VALIDATION"

if command -v terraform >/dev/null 2>&1; then
  terraform -chdir=aegis-x/terraform/bootstrap fmt -recursive -check
  terraform -chdir=aegis-x/terraform/bootstrap init -backend=false -input=false
  terraform -chdir=aegis-x/terraform/bootstrap validate
fi

section "9. EXISTING PROJECT TESTS"

if [[ -d tests ]]; then
  if command -v pytest >/dev/null 2>&1; then
    pytest -q
  else
    echo "[SKIPPED] pytest is not installed."
  fi
else
  echo "[INFO] No root tests directory found."
fi

section "AEGIS-X BUILD CHECK FINISHED"

echo "No Terraform apply was executed."
echo "No new billable cloud infrastructure was deployed."
echo "Review cloud credentials, plans, permissions and costs before deployment."
