---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "mondoo_space Resource - terraform-provider-mondoo"
subcategory: ""
description: |-
  Space resource
---

# mondoo_space (Resource)

Space resource

## Example Usage

```terraform
terraform {
  required_providers {
    mondoo = {
      source = "mondoohq/mondoo"
    }
  }
}

provider "mondoo" {
  region = "us"
}

resource "mondoo_space" "my_space" {
  name = "My Space New"
  // id = "your-space-id" # optional otherwise it will be auto-generated
  org_id = "your-org-1234567"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `org_id` (String) Id of the organization.

### Optional

- `name` (String) Name of the space.

### Read-Only

- `id` (String) Id of the space. Must be globally within the organization.