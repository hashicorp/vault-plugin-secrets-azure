# Configure Terraform
terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "3.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.1.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "2.84.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.8.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.7.2"
    }
  }
}

# Configure the Azure Active Directory Provider
provider "azuread" {
  tenant_id = var.tenant_id
}

# Configure the Azure Provider
provider "azurerm" {
  features {}
}

variable "tenant_id" {
  description = "Tenant ID that should be used."
}

variable "name_prefix" {
  description = "Prefix all resources with name."

}
variable "legacy_aad_resource_access" {
  description = "Provision AD application with Azure Active Directory Graph API access"
  type        = bool
  default     = false
}

resource "random_id" "name" {
  byte_length = 8
  prefix      = var.name_prefix
}

locals {
  name = random_id.name.dec
}

data "azurerm_subscription" "primary" {}

data "azurerm_client_config" "vault_azure_secrets" {}

data "azuread_client_config" "current" {}

resource "azuread_application" "vault_azure_secrets" {
  display_name     = local.name
  identifier_uris  = ["api://${local.name}"]
  owners           = [data.azuread_client_config.current.object_id]
  sign_in_audience = "AzureADMyOrg"

  feature_tags {
    enterprise = false
    gallery    = true
  }


  dynamic "required_resource_access" {
    for_each = var.legacy_aad_resource_access ? [] : [""]
    # Microsoft Graph
    content {
      resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

      resource_access {
        id   = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
        type = "Role"
      }

      resource_access {
        id   = "b4e74841-8e56-480b-be8b-910348b18b4c" # User.ReadWrite
        type = "Scope"
      }
    }
  }
  # Legacy Azure Active Directory Graph (AADG)
  dynamic "required_resource_access" {
    for_each = var.legacy_aad_resource_access ? [""] : []
    content {
      resource_app_id = "00000002-0000-0000-c000-000000000000"
      resource_access {
        id   = "311a71cc-e848-46a1-bdf8-97ff7156d8e6"
        type = "Scope"
      }
      resource_access {
        id   = "970d6fa6-214a-4a9b-8513-08fad511e2fd"
        type = "Scope"
      }
      resource_access {
        id   = "1cda74f2-2616-4834-b122-5cb1b07f8a59"
        type = "Role"
      }
      resource_access {
        id   = "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175"
        type = "Role"
      }
    }
  }
}

resource "time_rotating" "vault_azure_secrets" {
  rotation_days = 7
}

resource "azuread_application_password" "vault_azure_secrets" {
  application_object_id = azuread_application.vault_azure_secrets.object_id
  rotate_when_changed = {
    rotation = time_rotating.vault_azure_secrets.id
  }
}

resource "azuread_service_principal" "vault_azure_secrets" {
  description                  = local.name
  application_id               = azuread_application.vault_azure_secrets.application_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]
}

resource "azuread_group" "vault_azure_secrets" {
  display_name     = local.name
  owners           = [data.azuread_client_config.current.object_id]
  security_enabled = true

  members = [
    azuread_service_principal.vault_azure_secrets.object_id
  ]
}

resource "azurerm_resource_group" "vault_azure_secrets" {
  name     = local.name
  location = "East US"
}

data "azurerm_role_definition" "builtin" {
  name = "Owner"
}

resource "azurerm_role_assignment" "vault_azure_secrets" {
  scope              = azurerm_resource_group.vault_azure_secrets.id
  principal_id       = azuread_service_principal.vault_azure_secrets.object_id
  role_definition_id = "/subscriptions/${data.azurerm_subscription.primary.subscription_id}${data.azurerm_role_definition.builtin.id}"
}

resource "null_resource" "admin_consent" {
  depends_on = [
    azuread_application.vault_azure_secrets,
    azurerm_role_assignment.vault_azure_secrets,
  ]
  provisioner "local-exec" {
    command = <<HERE
for i in {0..60} ; do
  az ad app permission admin-consent --id "${azuread_application.vault_azure_secrets.application_id}" &> /dev/null && exit 0
  sleep .5
done
exit 1
HERE
  }
}

output "application_id" {
  value = azuread_application.vault_azure_secrets.application_id
}

output "application_password_value" {
  sensitive = true
  value     = azuread_application_password.vault_azure_secrets.value
}

output "application_password_id" {
  value = azuread_application_password.vault_azure_secrets.id
}

output "role_assignment_principal_type" {
  value = azurerm_role_assignment.vault_azure_secrets.principal_type
}

output "role_assignment_principal_id" {
  value = azurerm_role_assignment.vault_azure_secrets.principal_id
}

output "service_principal_id" {
  value = azuread_service_principal.vault_azure_secrets.id
}

output "resource_group_name" {
  value = azurerm_resource_group.vault_azure_secrets.name
}

output "tenant_id" {
  value = var.tenant_id
}

output "subscription_id" {
  value = data.azurerm_subscription.primary.subscription_id
}

output "name" {
  value = local.name
}
