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
  gha_subs = [
    for b in var.allowed_branches :
    "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/${b}"
  ]
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
