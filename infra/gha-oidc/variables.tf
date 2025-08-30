variable "aws_region" {
  type        = string
  description = "AWS region to operate in"
  default = "us-east-1"
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
  description = "ARN of the CMK used by the results bucket for SSE-KMS"
  type        = string
}

variable "tags" {
  type        = map(string)
  description = "Optional tags to apply"
  default     = {}
}
