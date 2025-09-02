variable "aws_region" {
  type        = string
  description = "AWS region to operate in"
  default     = "us-east-1"
}

variable "github_owner" {
  type        = string
  description = "GitHub org or user . e.g. 'thecturner'"
}

variable "github_repo" {
  type        = string
  description = "Repository name . e.g. 'sentra-scanner-test'"
}

variable "allowed_branches" {
  type        = list(string)
  description = "Branches allowed to assume the role"
  default     = ["main", "dev"]
}

variable "github_environment" {
  type        = string
  description = "Optional . GitHub Environment name to require . empty disables this gate"
  default     = ""
}

variable "role_name" {
  type        = string
  description = "IAM role name to create for GitHub Actions"
  default     = "gha-oidc-sentra-scanner"
}

variable "attach_example_permissions" {
  type        = bool
  description = "Attach a minimal example policy to the role . disabled by default"
  default     = false
}

variable "results_kms_arn" {
  type        = string
  default     = ""
  description = "Existing results CMK ARN. If empty and create_results_kms is true, we will create one."
}

variable "create_results_kms" {
  type        = bool
  default     = true
  description = "If true and results_kms_arn is empty, create a bootstrap CMK for dev."
}

variable "tags" {
  type        = map(string)
  description = "Optional tags to apply"
  default     = {}
}

variable "gha_oidc_role_name" {
  type        = string
  description = "Name of the GitHub OIDC execution role used by Terraform"
  default     = "gha-oidc-sentra-scanner"
}