#!/usr/bin/env bash
set -euo pipefail

echo "=== AEGIS-X Environment Preflight ==="

for cmd in git python3 terraform aws az gcloud docker; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[FOUND] $cmd: $(command -v "$cmd")"
  else
    echo "[MISSING] $cmd"
  fi
done

echo
echo "=== Git branch ==="
git branch --show-current

echo
echo "=== Terraform version ==="
if command -v terraform >/dev/null 2>&1; then
  terraform version
fi

echo
echo "Preflight complete. No cloud resources were created."
