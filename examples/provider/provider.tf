terraform {
  required_providers {
    mondoo = {
      source  = "mondoohq/mondoo"
      version = ">= 0.4.0"
    }
  }
}

provider "mondoo" {
  region = "us" # use "eu" for the European region
}