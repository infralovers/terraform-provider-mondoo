data "mondoo_policy" "policy" {
  space_id      = "your-space-1234567"
  catalog_type  = "ALL" # availabe options: "ALL", "POLICY", "QUERYPACK"
  assigned_only = true
}

output "policies_mrn" {
  value       = data.mondoo_policy.policy.policies.*.policy_mrn
  description = "The MRN of the policies in the space according to the filter criteria."
}
