terraform {
  required_providers {
    mondoo = {
      source = "mondoohq/mondoo"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

variable "gcp_project" {
  description = "GCP Project"
  type        = string
}

data "google_project" "project" {}

// Create a new service account
// https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_service_account_key
resource "google_service_account" "mondoo_integration" {
  account_id   = "mondoo-integration"
  display_name = "My Service Account"
}

// Create a new service account key for the service account
resource "google_service_account_key" "mykey" {
  service_account_id = google_service_account.mondoo_integration.name
}

# use the following command to see the output
# terraform output -raw google_service_account_key | base64 -d
output "google_service_account_key" {
  description = "Google Key"
  value       = google_service_account_key.mykey.private_key
  sensitive   = true
}

provider "mondoo" {
  region = "us"
}

variable "mondoo_org" {
  description = "Mondoo Organization"
  type        = string
}

// Create a new space
resource "mondoo_space" "my_space" {
  name   = "GCP ${data.google_project.project.name}"
  org_id = var.mondoo_org
}

// Setup the GCP integration
resource "mondoo_integration_gcp" "name" {
  space_id   = mondoo_space.my_space.id
  name       = "GCP ${data.google_project.project.name}"
  project_id = data.google_project.project.project_id
  credentials = {
    private_key = base64decode(google_service_account_key.mykey.private_key)
  }
}
