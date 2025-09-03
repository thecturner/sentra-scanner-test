# .tflint.hcl

plugin "aws" {
  enabled = true
  version = "0.35.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
  region  = "us-east-1"
}

config {
  module = true
}

# Core Terraform rules (tune as needed)
rule "terraform_required_version"    { enabled = true }
rule "terraform_unused_declarations" { enabled = true }
