provider "google" {
  project = var.project_id
  region  = var.region

  # Org-level APIs (Org Policy, SCC) are billed/quota'd against this project.
  user_project_override = true
  billing_project       = var.project_id
}
