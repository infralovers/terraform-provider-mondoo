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
