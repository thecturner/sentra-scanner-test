# Discover GitHub OIDC leaf certificate fingerprint automatically
data "tls_certificate" "github_oidc" {
  url = "https://token.actions.githubusercontent.com"
}


# Create the AWS OIDC provider that trusts GitHub
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # Use the leaf cert fingerprint so we do not guess the CA chain
  thumbprint_list = [
    data.tls_certificate.github_oidc.certificates[0].sha1_fingerprint
  ]
  tags = var.tags
}

# Build allowed subject claims for the branches
locals {
  use_inline_kms = var.results_kms_arn == "" && var.create_results_kms
  gha_subs = [
    for b in var.allowed_branches :
    "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/${b}"
  ]
}

resource "aws_kms_key" "results" {
  count                   = local.use_inline_kms ? 1 : 0
  description             = "Bootstrap CMK for results (gha-oidc)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "results" {
  count         = local.use_inline_kms ? 1 : 0
  name          = "alias/sentra-results-dev"
  target_key_id = aws_kms_key.results[0].key_id
}

# Single source of truth for the ARN we will authorize
locals {
  effective_results_kms_arn = (
    var.results_kms_arn != "" ? var.results_kms_arn :
    (local.use_inline_kms ? aws_kms_key.results[0].arn : "")
  )
  want_results_kms = var.create_results_kms || var.results_kms_arn != ""
}

data "aws_iam_policy_document" "kms_for_results" {
  count = local.want_results_kms ? 1 : 0

  statement {
    sid    = "AllowUseOfResultsCmkForS3"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
    ]
    resources = [local.effective_results_kms_arn]
  }
}

resource "aws_iam_policy" "kms_for_results" {
  count       = local.want_results_kms ? 1 : 0
  name        = "kms-for-results-cmk"
  description = "Use results CMK for S3 object encryption and decryption"
  policy      = data.aws_iam_policy_document.kms_for_results[0].json
}

resource "aws_iam_role_policy_attachment" "ec2_results_kms" {
  count      = local.want_results_kms ? 1 : 0
  role       = var.gha_oidc_role_name # or your OIDC role lookup
  policy_arn = aws_iam_policy.kms_for_results[0].arn
}

# Optional. export the ARN so the root stack can adopt it later
output "bootstrap_results_kms_arn" {
  value       = local.use_inline_kms ? aws_kms_key.results[0].arn : null
  description = "Bootstrap CMK ARN created by gha-oidc when create_results_kms = true"
}

# Look up the preexisting OIDC execution role by name
data "aws_iam_role" "gha_oidc" {
  name = var.gha_oidc_role_name
}

# Managed policy that grants EC2 read calls needed at plan time
resource "aws_iam_policy" "read_ec2_for_plan" {
  name        = "gha-oidc-read-ec2-for-plan"
  description = "Describe* permissions so Terraform can read VPC and subnets during plan"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "TerraformReadEc2ForPlan",
        Effect = "Allow",
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ec2:DescribeSecurityGroups"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach Managed policy that grants EC2 read calls needed at plan time to the execution role
resource "aws_iam_role_policy_attachment" "gha_oidc_attach_read_ec2" {
  role       = data.aws_iam_role.gha_oidc.name
  policy_arn = aws_iam_policy.read_ec2_for_plan.arn
}


# Policy allowing GitHub Actions role to use the results CMK for S3 I/O
data "aws_iam_policy_document" "gha_kms_for_results" {
  statement {
    sid    = "AllowUseOfResultsCmkForS3"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [var.results_kms_arn]
  }
}

resource "aws_iam_policy" "gha_kms_for_results" {
  name        = "${var.role_name}-kms-for-results-cmk"
  description = "Use results CMK for S3 object encryption and decryption"
  policy      = data.aws_iam_policy_document.gha_kms_for_results.json
}

resource "aws_iam_role_policy_attachment" "gha_kms_for_results" {
  role       = aws_iam_role.gha.name
  policy_arn = aws_iam_policy.gha_kms_for_results.arn
}

# Trust policy . restrict to repo . branches . and optional environment
data "aws_iam_policy_document" "gha_assume" {
  statement {
    sid     = "GitHubOIDCAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.gha_subs
    }

    dynamic "condition" {
      for_each = var.github_environment == "" ? [] : [1]
      content {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:environment"
        values   = [var.github_environment]
      }
    }
  }
}

# Role to be assumed by GitHub Actions
resource "aws_iam_role" "gha" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.gha_assume.json
  description        = "Assumable by GitHub Actions via OIDC for ${var.github_owner}/${var.github_repo}"
  tags               = var.tags
}

# Optional . attach a minimal example policy to the role
data "aws_iam_policy_document" "example" {
  statement {
    sid    = "ReadIdentityOnly"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "example" {
  count       = var.attach_example_permissions ? 1 : 0
  name        = "${var.role_name}-example"
  description = "Example minimal policy for GitHub Actions . adjust for your workloads"
  policy      = data.aws_iam_policy_document.example.json
}

resource "aws_iam_role_policy_attachment" "example" {
  count      = var.attach_example_permissions ? 1 : 0
  role       = aws_iam_role.gha.name
  policy_arn = aws_iam_policy.example[0].arn
}

