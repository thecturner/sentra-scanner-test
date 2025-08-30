output "gha_role_arn" {
  description = "Role to assume from GitHub Actions"
  value       = aws_iam_role.gha.arn
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN"
  value       = aws_iam_openid_connect_provider.github.arn
}
