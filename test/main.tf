provider "aws" {
  region = "us-east-1"
}

# One CMK for all test buckets
resource "aws_kms_key" "test_cmk" {
  description         = "CMK for encrypting test S3 buckets"
  enable_key_rotation = true
}

variable "bucket_names" {
  default = [
    "test-bucket-1-ct-us-east1-20250822",
    "test-bucket-2-ct-us-east1-20250822",
    "test-bucket-3-ct-us-east1-20250822"
  ]
}

locals {
  zip_map = {
    "test-bucket-1-ct-us-east1-20250822" = "test-bucket-1-ct-us-east1-20250822.zip"
    "test-bucket-2-ct-us-east1-20250822" = "test-bucket-2-ct-us-east1-20250822.zip"
    "test-bucket-3-ct-us-east1-20250822" = "test-bucket-3-ct-us-east1-20250822.zip"
  }
}

resource "aws_s3_bucket" "test_buckets" {
  for_each      = toset(var.bucket_names)
  bucket        = each.key
  force_destroy = true
}

# Public access block for every test bucket
resource "aws_s3_bucket_public_access_block" "test_pab" {
  for_each = aws_s3_bucket.test_buckets

  bucket                  = each.value.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "test_logs_pab" {
  for_each = aws_s3_bucket.test_logs

  bucket                  = each.value.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Default SSE for every test bucket using the CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "test_sse" {
  for_each = aws_s3_bucket.test_buckets

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.test_cmk.arn
    }
    bucket_key_enabled = true
  }

  depends_on = [aws_kms_key.test_cmk]

}

# Versioning on for every test bucket
resource "aws_s3_bucket_versioning" "test_versioning" {
  for_each = aws_s3_bucket.test_buckets

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "test_bucket_policy" {
  for_each = aws_s3_bucket.test_buckets

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      each.value.arn,
      "${each.value.arn}/*"
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
    resources = ["${each.value.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.test_cmk.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "test_policy" {
  for_each = aws_s3_bucket.test_buckets
  bucket   = each.value.id
  policy   = data.aws_iam_policy_document.test_bucket_policy[each.key].json

  depends_on = [aws_kms_key.test_cmk]

}

# Per-bucket logs bucket. keeps names predictable.
resource "aws_s3_bucket" "test_logs" {
  for_each = aws_s3_bucket.test_buckets

  bucket        = "${each.key}-logs"
  force_destroy = true
}



# Enable ACLs for log-delivery-write by preferring bucket owner
resource "aws_s3_bucket_ownership_controls" "test_logs_owner" {
  for_each = aws_s3_bucket.test_logs

  bucket = each.value.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "test_logs_acl" {
  for_each = aws_s3_bucket.test_logs
  bucket   = each.value.id
  acl      = "log-delivery-write"

  depends_on = [aws_s3_bucket_ownership_controls.test_logs_owner]

}

# Enable access logging to each test bucket's own logs bucket
resource "aws_s3_bucket_logging" "test_logging" {
  for_each = aws_s3_bucket.test_buckets

  bucket        = each.value.id
  target_bucket = aws_s3_bucket.test_logs[each.key].id
  target_prefix = "s3-access/"
}

resource "aws_s3_object" "zips" {
  for_each = local.zip_map

  bucket                 = each.key
  key                    = each.value
  source                 = "${path.module}/${each.value}"
  etag                   = filemd5("${path.module}/${each.value}")
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.test_cmk.arn

  depends_on = [aws_s3_bucket.test_buckets]
}

# Updated to use zsh script and read from output file
data "external" "unzipped_files" {
  program = ["zsh", "${abspath(path.module)}/unzip_and_list.zsh"]
}


resource "aws_s3_object" "unzipped" {
  for_each = {
    for full_key, file_info in data.external.unzipped_files.result :
    full_key => {
      bucket = split("/", full_key)[0]
      key    = split("/", full_key)[1]
      source = file_info
      etag   = filemd5(file_info)
    }
  }

  bucket                 = each.value.bucket
  key                    = each.value.key
  source                 = each.value.source
  etag                   = each.value.etag
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.test_cmk.arn

  depends_on = [aws_s3_bucket.test_buckets]
}
