variable "test_bucket_names" {
  type        = list(string)
  description = "Names for the test S3 buckets. Each name also creates a companion <name>-logs bucket."
  default     = []

  # Basic S3-safe validation. Lowercase letters, numbers, and hyphens only.
  # 3–63 chars. Must start and end with a letter or number.
  validation {
    condition = alltrue([
      for n in var.test_bucket_names :
      can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", n))
    ])
    error_message = "Each bucket name must be 3–63 characters. Lowercase letters, numbers, and hyphens only. Must start and end with a letter or number."
  }
}
