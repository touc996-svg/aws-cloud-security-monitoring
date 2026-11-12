#!/usr/bin/env bash
set -euo pipefail

echo "=== AEGIS-X Environment Preflight ==="

check() {
  local name="$1"
  local command_name="$2"
  if command -v "$command_name" >/dev/null 2>&1; then
    printf 'FOUND   %-18s %s\n' "$name" "$(command -v "$command_name")"
  else
    printf 'MISSING %-18s %s\n' "$name" "$command_name"
  fi
}

check "Git" git
check "Terraform" terraform
check "AWS CLI" aws
check "Azure CLI" az
check "Google Cloud CLI" gcloud
check "Python" python3
check "Docker" docker
check "OPA" opa
check "Conftest" conftest
check "Checkov" checkov

echo
echo "=== Git branch ==="
git branch --show-current

echo
echo "=== Terraform version ==="
if command -v terraform >/dev/null 2>&1; then
  terraform version
fi

printf '\n=== Authentication (optional until deployment; read-only) ===\n'
if command -v aws >/dev/null 2>&1; then aws sts get-caller-identity --output table 2>&1 || true; fi
if command -v az >/dev/null 2>&1; then az account show --output table 2>&1 || true; fi
if command -v gcloud >/dev/null 2>&1; then gcloud auth list 2>&1 || true; fi

echo
echo "Preflight complete. No cloud resources were created."
