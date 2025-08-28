terraform {
  # Require a reasonably current core. Adjust if you know you need lower.
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # Use a caret or pessimistic range for stability with updates.
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    template = {
      source  = "hashicorp/template"
      # 2.2.0 is the latest and effectively frozen. Keep it pinned.
      version = "~> 2.2"
    }
    # If you end up migrating to cloudinit instead of template_cloudinit_config,
    # switch to:
    # cloudinit = {
    #   source  = "hashicorp/cloudinit"
    #   version = "~> 2.3"
    # }
  }
}
