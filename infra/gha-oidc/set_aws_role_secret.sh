#!/usr/bin/env bash
# set_aws_role_secret.sh
# Purpose: Pull a Terraform output (gha_role_arn) and set it as a GitHub repo or environment secret named AWS_ROLE_ARN.
# Prereqs: terraform, gh CLI logged in with a token that has 'repo' scope for private repos.
# Usage examples:
#   ./set_aws_role_secret.sh -r thecturner/sentra-scanner-test
#   ./set_aws_role_secret.sh -r thecturner/sentra-scanner-test -d infra/gha-oidc -o gha_role_arn -s AWS_ROLE_ARN
#   ./set_aws_role_secret.sh -r thecturner/sentra-scanner-test -e aws-prod
#
set -euo pipefail

REPO=""
TF_DIR="infra/gha-oidc"
OUTPUT_NAME="gha_role_arn"
SECRET_NAME="AWS_ROLE_ARN"
ENV_NAME=""   # optional GitHub Environment

usage() {
  cat <<USAGE
Usage: $0 -r <owner/repo> [-d <tf_dir>] [-o <output_name>] [-s <secret_name>] [-e <environment_name>]
  -r  Required. GitHub repository in form owner/repo
  -d  Optional. Terraform working directory. Default: infra/gha-oidc
  -o  Optional. Terraform output name. Default: gha_role_arn
  -s  Optional. GitHub secret name. Default: AWS_ROLE_ARN
  -e  Optional. GitHub Environment name to set an environment-scoped secret
USAGE
}

while getopts ":r:d:o:s:e:h" opt; do
  case $opt in
    r) REPO="$OPTARG" ;;
    d) TF_DIR="$OPTARG" ;;
    o) OUTPUT_NAME="$OPTARG" ;;
    s) SECRET_NAME="$OPTARG" ;;
    e) ENV_NAME="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option -$OPTARG" >&2; usage; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$REPO" ]]; then
  echo "Error: -r <owner/repo> is required."
  usage
  exit 1
fi

command -v terraform >/dev/null 2>&1 || { echo "terraform not found in PATH"; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "gh CLI not found in PATH"; exit 1; }

# Verify gh auth
if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated. Run 'gh auth login' first."
  exit 1
fi

# Pull the Terraform output
if [[ ! -d "$TF_DIR" ]]; then
  echo "Terraform dir '$TF_DIR' not found"
  exit 1
fi

ROLE_ARN="$(terraform -chdir="$TF_DIR" output -raw "$OUTPUT_NAME" 2>/dev/null || true)"
if [[ -z "${ROLE_ARN:-}" ]]; then
  echo "Failed to read Terraform output '$OUTPUT_NAME' from '$TF_DIR'"
  exit 1
fi

echo "Setting secret '$SECRET_NAME' in repo '$REPO'..."
if [[ -n "$ENV_NAME" ]]; then
  echo "Targeting GitHub Environment: $ENV_NAME"
  gh secret set "$SECRET_NAME" --repo "$REPO" --env "$ENV_NAME" --body "$ROLE_ARN"
else
  gh secret set "$SECRET_NAME" --repo "$REPO" --body "$ROLE_ARN"
fi

echo "Done. Secret '$SECRET_NAME' has been set for $REPO${ENV_NAME:+ (env: $ENV_NAME)}."
