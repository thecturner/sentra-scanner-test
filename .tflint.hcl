# Enable the bundled Terraform-language rules (recommended preset)
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# AWS provider ruleset (keep your pin or bump as you wish)
plugin "aws" {
  enabled = true
  version = "0.35.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
  region  = "us-east-1"
}

config {
  # v0.59+ replacement for the old "module" flag
  # "local" = lint local modules without requiring remote downloads
  # ("all" needs modules to be inited; "none" disables module calls)
  call_module_type = "local"
}

# Optional examples if you want to toggle core rules explicitly
rule "terraform_required_version"    { enabled = true }
rule "terraform_unused_declarations" { enabled = true }
