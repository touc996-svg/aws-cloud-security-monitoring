# azure-security

Code-only Terraform module for the AEGIS-X Azure security baseline: Log Analytics
workspace, Microsoft Sentinel onboarding, Defender for Cloud plans and a subscription
Activity Log diagnostic setting.

> **This module cannot be planned or applied against a real subscription yet.**
> The only Azure account available to the project is tenant-level
> (tenant `81b0daa5-5660-4a8d-85f2-b4c5c868766f`) with **no usable subscription**, and every
> resource here is subscription-scoped. Verified so far: `terraform fmt`, `init -backend=false`,
> `validate` and Checkov (see below). **Not verified:** `terraform plan`/`apply`, provider
> behaviour, RBAC, quota, and actual cost. Treat the first plan on a real subscription as the
> first real test.

## Feature gates (all default `false`)

| Variable | Creates | Billable |
|---|---|---|
| `enable_log_analytics_workspace` | resource group + Log Analytics workspace (`PerGB2018`, daily cap `daily_quota_gb`, default 1 GB) | per GB ingested/retained |
| `enable_sentinel` | `azurerm_sentinel_log_analytics_workspace_onboarding` | per GB analysed, on top of Log Analytics |
| `enable_defender_plans` + `defender_plans` | Defender for Cloud plans at `Standard` (default `Arm`, `KeyVaults`) | per plan, usage- or resource-based |
| `enable_activity_log_diagnostics` | diagnostic setting sending Activity Log categories to the workspace | ingestion cost |

`enable_sentinel` and `enable_activity_log_diagnostics` require the workspace (enforced by variable validation).
Foundational CSPM (secure score, recommendations) is free and on by default in Azure; this module does not manage it.
Supported `defender_plans`: `Api, AppServices, Arm, CloudPosture, Containers, CosmosDbs, KeyVaults, OpenSourceRelationalDatabases, SqlServers, SqlServerVirtualMachines, StorageAccounts, VirtualMachines`.
`CloudPosture` is the paid *Defender CSPM* plan.

## Prerequisites (not managed here)

- A subscription you can bill, with Owner or (Contributor + User Access Administrator); Sentinel onboarding needs Contributor on the workspace.
- Resource providers registered (the module sets `resource_provider_registrations = "none"`): `Microsoft.OperationalInsights`, `Microsoft.SecurityInsights`, `Microsoft.Security`, `Microsoft.Insights`.
- Credentials via `az login` or `ARM_*` environment variables. Never commit credentials or `terraform.tfvars`.

## Service availability / licensing assumptions (checked 2026-11-12)

Checked against Microsoft Learn / azure.microsoft.com search results; the pricing pages render prices client-side, so **dollar figures could not be confirmed this session**.

- **Sentinel** is billed per GB ingested for analysis, *in addition to* Log Analytics ingestion, with pay-as-you-go and commitment tiers (from 100 GB/day). Confirmed from Microsoft's billing/pricing pages.
- **Portal change:** Microsoft states that from **July 2026** customers using Sentinel in the Azure portal are redirected to the **Defender portal**. Workspace onboarding via Terraform/ARM still applies, but day-to-day SecOps happens in the Defender portal; connecting the workspace there is a manual/tenant-level step outside this module. Re-verify this before relying on Azure-portal-specific workflows.
- **Defender for Cloud:** Foundational CSPM is free; Defender CSPM and workload plans are paid, billed per billable resource (e.g. VMs, storage accounts, databases) or by usage; a 30-day free trial is advertised. Defender for Servers Plan 2 includes 500 MB/VM/day of free Log Analytics ingestion for security data.
- **Activity Log → workspace** diagnostic settings are available on every subscription; the Activity Log itself is free, ingestion into Log Analytics is not.

## Cost estimate (sandbox, order of magnitude only)

**Re-check pricing** at <https://azure.microsoft.com/pricing/details/microsoft-sentinel/>, <https://azure.microsoft.com/pricing/details/monitor/> and <https://azure.microsoft.com/pricing/details/defender-for-cloud/> and in the Azure pricing calculator before applying. Third-party sources disagreed ($2.46–$5.59/GB); figures below are assumptions, not confirmed list prices.

| Item | Assumption | Approx. / month |
|---|---|---|
| Log Analytics + Sentinel ingestion | ≤ 1 GB/day (the module's cap) ≈ 30 GB × ~$4.30/GB combined PAYG (East US figure reported by several sources) | ~$130 at the cap; typically far less for an idle sandbox |
| Retention beyond 31 days | 90 d retention, small volume | a few $ |
| Defender `Arm` + `KeyVaults` | usage-based (per 1M ARM operations / per 10k Key Vault transactions) | ~$0–10 idle |
| Defender CSPM / Servers / Storage etc. | per billable resource (recalled list prices: CSPM ~$5/resource, Servers P2 ~$15/server — **unverified**) | $0 unless enabled |

Without the Activity Log diagnostic setting and with Sentinel off, an idle workspace is close to $0. The 1 GB/day cap is the main spend guard; ingestion stops when it is hit (security data is then lost for the rest of the day).

## Validation performed

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
checkov -d aegis-x/terraform/azure-security --framework terraform   # 10 passed, 0 failed, 0 skipped
```

No Checkov skips are needed. Note Checkov only scans resources it can see in the static config; with all gates `false` the `count`/`for_each` resources are still parsed, but cost/behaviour checks on a real plan have not been run.

## Next step once a subscription exists

Set `subscription_id`, flip one gate at a time, run `terraform plan`, review, and only then apply from a pipeline or by hand with approval.
