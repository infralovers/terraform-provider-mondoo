provider "mondoo" {
  region = "us"
}

resource "mondoo_space" "my_space" {
  name   = "My Space Name"
  org_id = "your-org-1234567"
}

resource "mondoo_policy_assignment" "space" {
  space_id = mondoo_space.my_space.id

  policies = [
    "//policy.api.mondoo.app/policies/mondoo-aws-security",
  ]

  state = "enabled" # default is enabled, we also support preview and disabled

  depends_on = [
    mondoo_space.my_space
  ]
}
