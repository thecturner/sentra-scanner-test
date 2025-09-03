
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

module "test_buckets" {
  source = "./test"
  test_bucket_names = [
    "test-bucket-1-ct-us-east1-20250822",
    "test-bucket-2-ct-us-east1-20250822",
    "test-bucket-3-ct-us-east1-20250822"
  ] # or pass via TF_VAR_test_bucket_names
}

#data "template_file" "user_data" {
#  template = file("${path.module}/user_data.sh.tmpl")
#
#  vars = {
#    results_bucket_name = var.results_bucket_name
#  }
#}
# KMS key to encrypt objects in the results bucket.
resource "aws_kms_key" "results_cmk" {
  count                    = var.create_results_kms ? 1 : 0
  description              = "CMK for encrypting S3 results bucket objects"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
}

resource "aws_s3_bucket" "results" {
  bucket        = var.results_bucket_name
  force_destroy = true
}

# Block all forms of public access on the results bucket.
resource "aws_s3_bucket_public_access_block" "results_pab" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.results]
}

# Default server-side encryption for all new objects.
resource "aws_s3_bucket_server_side_encryption_configuration" "results_sse" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.effective_results_kms_arn
    }
    bucket_key_enabled = true
  }

  depends_on = [aws_kms_key.results_cmk]
}

resource "aws_s3_bucket_versioning" "results_ver" {
  bucket = aws_s3_bucket.results.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "scanner_py" {
  bucket = aws_s3_bucket.results.id
  key    = "artifacts/scanner/scanner.py"
  source = "${path.module}/scanner.py"

  # Use source_hash instead of etag when KMS is enabled
  source_hash = filebase64sha256("${path.module}/scanner.py")

  content_type           = "text/x-python"
  server_side_encryption = "aws:kms"
  kms_key_id             = local.effective_results_kms_arn

  depends_on = [aws_s3_bucket.results]
}

data "aws_iam_policy_document" "results_bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.results.arn,
      "${aws_s3_bucket.results.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnencryptedObjectUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.results.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.effective_results_kms_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "results_policy" {
  bucket = aws_s3_bucket.results.id
  policy = data.aws_iam_policy_document.results_bucket_policy.json

  depends_on = [aws_kms_key.results_cmk]
}

# Build a least-privilege policy for using the results CMK
data "aws_iam_policy_document" "kms_for_results" {
  count = local.want_kms ? 1 : 0

  statement {
    sid    = "AllowUseOfResultsCmkForS3"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
    ]
    resources = [local.effective_results_kms_arn]
  }
}

resource "aws_iam_policy" "kms_for_results" {
  count       = local.want_kms ? 1 : 0
  name        = "kms-for-results-cmk"
  description = "Use results CMK for S3 object encryption and decryption"
  policy      = data.aws_iam_policy_document.kms_for_results[0].json
}

resource "null_resource" "scanner_file_hash" {
  triggers = {
    scanner_hash = filesha256("${path.module}/scanner.py")
  }
}

resource "aws_iam_role" "ec2_role" {
  name = "scanner-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

# Attach to the EC2 role used by aws_iam_instance_profile.ec2_profile
resource "aws_iam_role_policy_attachment" "ec2_results_kms" {
  count      = local.want_kms ? 1 : 0
  role       = "scanner-ec2-role" # or aws_iam_role.ec2_role.name if you created it in TF
  policy_arn = aws_iam_policy.kms_for_results[0].arn
}

resource "aws_iam_policy" "scanner_policy" {
  name        = "scanner-policy"
  description = "Policy allowing scanner to access S3 buckets"
  policy      = file("${path.module}/scanner_policy.json")
}

resource "aws_iam_role_policy_attachment" "scanner_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.scanner_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "scanner-instance-profile"
  role = aws_iam_role.ec2_role.name
}

data "external" "my_ip" {
  program = ["bash", "${path.module}/get_my_ip.sh"]
}

resource "aws_security_group" "scanner_sg" {
  name        = "scanner-security-group"
  description = "Allow SSH access from my IP"
  vpc_id      = data.aws_vpc.default.id # Replace with actual VPC if needed

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [data.external.my_ip.result["cidr"]]
  }

  # Reason. Scanner needs temporary outbound HTTPS for package bootstrap and S3 access.
  # Proper hardening will replace this with VPC endpoints and prefix-listed egress.
  # tfsec:ignore:AVD-AWS-0104
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Temporary. Outbound HTTPS only. Replaced by VPC endpoints later."
  }

  tags = {
    Name = "scanner-sg"
  }
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_key_pair" "scanner_key" {
  count      = local.create_scanner_key ? 1 : 0
  key_name   = "scanner-key"
  public_key = var.public_key
  tags = {
    Project = "sentra-scanner-test"
  }
}

locals {
  # Use external ARN if given. Else use the created key’s ARN.
  effective_results_kms_arn = var.create_results_kms ? aws_kms_key.results_cmk[0].arn : var.results_kms_arn

  # True only when we intend to create a bootstrap KMS key in this stack
  use_inline_kms = var.results_kms_arn == "" && var.create_results_kms

  # True when we will have some KMS key involved at all
  # This depends only on variables, so it is plan-time known
  want_kms           = var.results_kms_arn != "" || var.create_results_kms
  create_scanner_key = var.public_key != ""
}

locals {
  user_data_scanner_python38 = <<EOF
#!/bin/bash
exec > >(tee -a /var/log/user-data.log) 2>&1
set -euxo pipefail

# Python 3.8 and tools
amazon-linux-extras enable python3.8
yum clean metadata
yum -y install python3.8 curl unzip tar gzip awscli

# Pip for 3.8 on AL2
curl -fsSL https://bootstrap.pypa.io/pip/3.8/get-pip.py -o /root/get-pip.py
python3.8 /root/get-pip.py
python3.8 -m pip install --upgrade pip boto3

# App dirs
install -d -m 755 /opt/sentra
install -d -m 755 /var/log/s3scanner

# Pull scanner with retries
for i in 1 2 3 4 5; do
  aws s3 cp "s3://${var.results_bucket_name}/artifacts/scanner/scanner.py" /opt/sentra/scanner.py --region "${var.aws_region}" \
    && break || { echo "retry $i"; sleep 5; }
done
chmod 755 /opt/sentra/scanner.py

# Wrapper selects dev or s3 mode
cat >/opt/sentra/run_scanner.sh <<'RUNEOF'
#!/usr/bin/env bash
set -euo pipefail

PY="/usr/bin/python3.8"
SCRIPT="/opt/sentra/scanner.py"

OPTS=()
if [[ "$${SCANNER_DEV_MODE:-0}" == "1" || "$${SCANNER_DEV_MODE:-false}" == "true" ]]; then
  OUT_DIR="$${SCANNER_OUT_DIR:-/var/log/s3scanner}"
  mkdir -p "$${OUT_DIR}"
  OPTS+=(--dev --out "$${OUT_DIR}")
else
  if [[ -z "$${RESULTS_BUCKET:-}" ]]; then
    echo "RESULTS_BUCKET is required for non-dev runs" >&2
    exit 2
  fi
  OPTS+=(--results-bucket "$${RESULTS_BUCKET}")
fi

OPTS+=(--max-workers "$${SCANNER_MAX_WORKERS:-16}")
OPTS+=(--sample-bytes "$${SCANNER_SAMPLE_BYTES:-1048576}")
OPTS+=(--archive-bytes-limit "$${SCANNER_ARCHIVE_BYTES_LIMIT:-1048576}")
OPTS+=(--inner-member-read-limit "$${SCANNER_INNER_MEMBER_READ_LIMIT:-131072}")
OPTS+=(--total-archive-read-budget "$${SCANNER_TOTAL_ARCHIVE_READ_BUDGET:-1048576}")

export AWS_DEFAULT_REGION="$${AWS_REGION:-$${AWS_DEFAULT_REGION:-}}"
export SCANNER_WRITE_LEGACY_OUTPUTS="$${SCANNER_WRITE_LEGACY_OUTPUTS:-1}"

exec "$${PY}" "$${SCRIPT}" "$${OPTS[@]}"
RUNEOF
chmod +x /opt/sentra/run_scanner.sh

# systemd unit
cat >/etc/systemd/system/scanner.service <<'UNIT'
[Unit]
Description=Sentra S3 Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/sentra
Environment=AWS_REGION=${var.aws_region}
Environment=RESULTS_BUCKET=${var.results_bucket_name}
Environment=SCANNER_DEV_MODE=${var.scanner_dev_mode}
Environment=SCANNER_OUT_DIR=${var.scanner_out_dir}
Environment=SCANNER_MAX_WORKERS=${var.scanner_max_workers}
Environment=SCANNER_SAMPLE_BYTES=${var.scanner_sample_bytes}
Environment=SCANNER_ARCHIVE_BYTES_LIMIT=${var.scanner_archive_bytes_limit}
Environment=SCANNER_INNER_MEMBER_READ_LIMIT=${var.scanner_inner_member_read_limit}
Environment=SCANNER_TOTAL_ARCHIVE_READ_BUDGET=${var.scanner_total_archive_read_budget}
Environment=SCANNER_WRITE_LEGACY_OUTPUTS=${var.scanner_write_legacy_outputs}
Environment=PYTHONUNBUFFERED=1
ExecStart=/bin/bash -lc '/opt/sentra/run_scanner.sh >> /var/log/scanner.log 2>&1'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now scanner
EOF
}

#data "template_cloudinit_config" "scanner_userdata" {
#  gzip          = true
#  base64_encode = true
#
#  part {
#    content_type = "text/cloud-config"
#    content      = <<-EOF
##cloud-config
#packages:
#  - python3
#  - python3-pip
#  - awscli
#  - unzip
#  - tar
#  - gzip
#
#write_files:
#  - path: /etc/systemd/system/scanner.service
#    permissions: "0644"
#    owner: root:root
#    content: |
#      [Unit]
#      Description=Sentra Sample S3 Scanner
#      After=network-online.target cloud-final.service
#      Wants=network-online.target
#      ConditionPathExists=/opt/sentra/scanner.py
#
#      [Service]
#      Type=simple
#      User=ec2-user
#      Environment=PYTHONUNBUFFERED=1
#      ExecStart=/usr/bin/python3 /opt/sentra/scanner.py
#      Restart=on-failure
#      RestartSec=5s
#      StandardOutput=append:/var/log/scanner.log
#      StandardError=append:/var/log/scanner.log
#
#      [Install]
#      WantedBy=multi-user.target
#
#runcmd:
#  - mkdir -p /opt/sentra
#  - chown ec2-user:ec2-user /opt/sentra
#  - 'for i in 1 2 3 4 5; do aws s3 cp "s3://${aws_s3_bucket.results.bucket}/artifacts/scanner/scanner.py" /opt/sentra/scanner.py --region "${var.aws_region}" && break || (echo "retry $i"; sleep 5); done'
#  - chmod +x /opt/sentra/scanner.py
#  - pip3 install --upgrade pip
#  - pip3 install --no-cache-dir boto3
#  - systemctl daemon-reload
#  - systemctl enable --now scanner
#EOF
#  }
#}

resource "aws_instance" "scanner_vm" {
  ami                                  = var.ami_id
  instance_type                        = var.instance_type
  iam_instance_profile                 = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids               = [aws_security_group.scanner_sg.id]
  key_name                             = local.create_scanner_key ? aws_key_pair.scanner_key[0].key_name : null
  user_data                            = local.user_data_scanner_python38
  instance_initiated_shutdown_behavior = "terminate"


  metadata_options {
    http_endpoint               = "enabled"  # keep IMDS (instance metedata service) reachable on the instance
    http_tokens                 = "required" # force IMDSv2. block IMDSv1 making blind Server-Side Request Forgery harder
    http_put_response_hop_limit = 2          # typical default. limits token reuse via proxies
  }

  root_block_device {
    encrypted = true
    # Using the S3 CMK we create. Otherwise omit kms_key_id to use default EBS CMK.
    kms_key_id            = try(local.effective_results_kms_arn, null)
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true

  }

  tags = {
    Name = "scanner-vm"
  }

  depends_on = [null_resource.scanner_file_hash]
}

resource "aws_s3_bucket" "results_logs" {
  bucket        = "${var.results_bucket_name}-logs"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "results_logs_owner" {
  bucket = aws_s3_bucket.results_logs.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_acl" "results_logs_acl" {
  bucket     = aws_s3_bucket.results_logs.id
  acl        = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.results_logs_owner]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results_logs_sse" {
  bucket = aws_s3_bucket.results_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.effective_results_kms_arn
    }
    bucket_key_enabled = true
  }

  depends_on = [aws_kms_key.results_cmk]
}

resource "aws_s3_bucket_versioning" "results_logs_ver" {
  bucket = aws_s3_bucket.results_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "results_logs_pab" {
  bucket                  = aws_s3_bucket.results_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "results_logging" {
  bucket        = aws_s3_bucket.results.id
  target_bucket = aws_s3_bucket.results_logs.id
  target_prefix = "s3-access/"
}

data "aws_iam_policy_document" "self_terminate_doc" {
  statement {
    sid     = "AllowTerminateTaggedInstancesOnly"
    actions = ["ec2:TerminateInstances"]
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AutoTerminate"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "self_terminate" {
  name        = "scanner-self-terminate"
  description = "EC2 can terminate instances tagged AutoTerminate=true"
  policy      = data.aws_iam_policy_document.self_terminate_doc.json
}
