# Variables
# ----------------------------------------------

variable "tenant_id" {
  description = "The Azure Active Directory Tenant ID"
  type        = string
  default     = "ffffffff-ffff-ffff-ffff-ffffffffffff"
}

locals {
  mondoo_security_integration_name = "Mondoo Security Integration"
}

# Azure AD with Application and Certificate
# ----------------------------------------------

provider "azuread" {
  tenant_id = var.tenant_id
}

data "azuread_client_config" "current" {}

# Add the required permissions to the application
# User still need to be grant the permissions to the application via the Azure Portal
resource "azuread_application" "mondoo_security" {
  display_name = "Ms365 ${local.mondoo_security_integration_name}"

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68"
      type = "Role"
    }

    resource_access {
      id   = "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0"
      type = "Role"
    }

    resource_access {
      id   = "5e0edab9-c148-49d0-b423-ac253e121825"
      type = "Role"
    }

    resource_access {
      id   = "bf394140-e372-4bf9-a898-299cfc7564e5"
      type = "Role"
    }

    resource_access {
      id   = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
      type = "Role"
    }

    resource_access {
      id   = "9e640839-a198-48fb-8b9a-013fd6f6cbcd"
      type = "Role"
    }

    resource_access {
      id   = "37730810-e9ba-4e46-b07e-8ca78d182097"
      type = "Role"
    }
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0ff1-ce00-000000000000"

    resource_access {
      id   = "678536fe-1083-478a-9c59-b99265e6b0d3"
      type = "Role"
    }
  }

  required_resource_access {
    resource_app_id = "00000002-0000-0ff1-ce00-000000000000"

    resource_access {
      id   = "dc50a0fb-09a3-484d-be87-e023b12c6440"
      type = "Role"
    }
  }

}

resource "tls_private_key" "credential" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "credential" {
  private_key_pem = tls_private_key.credential.private_key_pem

  # Certificate expires after 3 months.
  validity_period_hours = 1680

  # Generate a new certificate if Terraform is run within three
  # hours of the certificate's expiration time.
  early_renewal_hours = 3

  # Reasonable set of uses for a server SSL certificate.
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "data_encipherment",
    "cert_signing",
  ]

  subject {
    common_name = "mondoo"
  }
}

# Attach the certificate to the application
resource "azuread_application_certificate" "mondoo_security_integration" {
  # see https://github.com/hashicorp/terraform-provider-azuread/issues/1227
  application_id = azuread_application.mondoo_security.id
  type           = "AsymmetricX509Cert"
  value          = tls_self_signed_cert.credential.cert_pem
}

# Create a service principal for the application
resource "azuread_service_principal" "mondoo_security" {
  client_id                    = azuread_application.mondoo_security.client_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]
}

# Azure Permissions to Azure AD Application
# ----------------------------------------------

provider "azurerm" {
  tenant_id = var.tenant_id
  features {}
}

resource "azuread_directory_role" "global_reader" {
  display_name = "Global Reader"
}

resource "azuread_directory_role_assignment" "global_reader" {
  role_id             = azuread_directory_role.global_reader.template_id
  principal_object_id = azuread_service_principal.mondoo_security.object_id
}

# Configure the Mondoo
# ----------------------------------------------

provider "mondoo" {
  space = "hungry-poet-123456"
}

# Setup the Azure integration
resource "mondoo_integration_ms365" "ms365_integration" {
  name      = "Ms365 ${local.mondoo_security_integration_name}"
  tenant_id = var.tenant_id
  client_id = azuread_application.mondoo_security.client_id
  credentials = {
    pem_file = join("\n", [tls_self_signed_cert.credential.cert_pem, tls_private_key.credential.private_key_pem])
  }
  # wait for the permissions to provisioned
  depends_on = [
    azuread_application.mondoo_security,
    azuread_service_principal.mondoo_security,
    azuread_directory_role_assignment.global_reader,
  ]
}
