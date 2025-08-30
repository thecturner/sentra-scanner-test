# AWS OIDC for GitHub Actions. standalone Terraform pack

## Why keep this separate
- Clean separation of duties. Your CI/IaC runner identity is managed apart from app infra.
- Isolated Terraform state. Safer blast radius. Easier rollback.
- Optionality. You can delete or ignore this directory if you stop using GitHub Actions.
- Auditable lifecycle. OIDC provider and role changes are reviewed independently.

## Where to put it
- **Recommended**. Keep this in its own directory outside `.github`, for example `infra/gha-oidc/` or `terraform/gha-oidc/`.
- **Acceptable**. Inside this repo at `infra/gha-oidc/`. Use a separate backend/state from your app stacks.
- **Not recommended**. Under `.github/`. That folder is conventionally for workflow YAML. Mixing Terraform there can surprise future readers and tooling.

If you insist on `.github/`, you can place this folder at `.github/gha-oidc/` and run Terraform from there. It will still work, but the discoverability is worse.

## What this creates
- An IAM **OpenID Connect Provider** for `https://token.actions.githubusercontent.com`.
- An IAM **Role** assumable via `sts:AssumeRoleWithWebIdentity` by your GitHub repo on specific branches.
- **Optional**. A minimal example policy attachment. Disabled by default.

## Inputs you set
- `github_owner` . your org or user, e.g., `thecturner`
- `github_repo` . repo name, e.g., `sentra-scanner-test`
- `allowed_branches` . list of branches that can assume, default `["main", "dev"]`
- `github_environment` . optional environment gate, default empty disables it
- `role_name` . IAM role name, default `gha-oidc-sentra-scanner`
- `aws_region` . e.g., `us-east-1`
- `attach_example_permissions` . bool . default `false` . when `true` attaches a minimal demo policy

## Usage
```bash
cd infra/gha-oidc    # or wherever you placed this
terraform init
terraform apply -var='github_owner=thecturner' -var='github_repo=sentra-scanner-test' -var='aws_region=us-east-1'
```

## Output to paste into GitHub Secrets
- `gha_role_arn` . set this as `AWS_ROLE_ARN` in your repo secrets.

## GitHub Actions snippet
```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4
  - name: Configure AWS credentials via OIDC
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
      aws-region: us-east-1
  - run: aws sts get-caller-identity
```
