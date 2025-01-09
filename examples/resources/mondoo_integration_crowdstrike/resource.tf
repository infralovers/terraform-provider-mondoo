variable "client_secret" {
  description = "CrowdStrike Client Secret"
  type        = string
  sensitive   = true
}

provider "mondoo" {
  space = "hungry-poet-123456"
}

# Setup the AWS integration
resource "mondoo_integration_crowdstrike" "crowdstrike" {
  name          = "CrowdStrike Integration"
  client_id     = "123456"
  base_url      = "https://api.your-region.crowdstrike.com"
  customer_id   = "123456"
  create_assets = true

  credentials = {
    client_secret = var.client_secret
  }
}
