---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "mondoo_integration_sentinelone Resource - terraform-provider-mondoo"
subcategory: ""
description: |-
  Continuously scan Sentinel One subscriptions and resources for misconfigurations and vulnerabilities.
---

# mondoo_integration_sentinelone (Resource)

Continuously scan Sentinel One subscriptions and resources for misconfigurations and vulnerabilities.

## Example Usage

```terraform
variable "client_secret" {
  description = "The SentinelOne Client Secret"
  type        = string
  sensitive   = true
}

provider "mondoo" {
  space = "hungry-poet-123456"
}

# Setup the SentinelOne integration
resource "mondoo_integration_sentinelone" "sentinelone_integration" {
  name    = "SentinelOne Integration"
  host    = "https://example.sentinelone.net"
  account = "example"

  credentials = {
    client_secret = var.client_secret
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account` (String) Sentinel One account.
- `credentials` (Attributes) Credentials for Sentinel One integration. Remote changes will not be detected. (see [below for nested schema](#nestedatt--credentials))
- `host` (String) Sentinel One host.
- `name` (String) Name of the integration.

### Optional

- `space_id` (String) Mondoo space identifier. If there is no space ID, the provider space is used.

### Read-Only

- `mrn` (String) Integration identifier

<a id="nestedatt--credentials"></a>
### Nested Schema for `credentials`

Optional:

- `client_secret` (String, Sensitive) Client secret for Sentinel One integration.
- `pem_file` (String, Sensitive) PEM file for Sentinel One integration.