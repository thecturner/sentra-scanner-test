provider "aws" {
  region = "us-east-1"
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

# One CMK for all test buckets
resource "aws_kms_key" "test_cmk" {
  description         = "CMK for encrypting test S3 buckets"
  enable_key_rotation = true
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
}

# Versioning on for every test bucket
resource "aws_s3_bucket_versioning" "test_versioning" {
  for_each = aws_s3_bucket.test_buckets

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Per-bucket logs bucket. keeps names predictable.
resource "aws_s3_bucket" "test_logs" {
  for_each = aws_s3_bucket.test_buckets

  bucket        = "${each.key}-logs"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "test_logs_acl" {
  for_each = aws_s3_bucket.test_logs
  bucket   = each.value.id
  acl      = "log-delivery-write"
}

resource "aws_s3_bucket_public_access_block" "test_logs_pab" {
  for_each = aws_s3_bucket.test_logs

  bucket                  = each.value.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
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

  bucket = each.key
  key    = each.value
  source = "${path.module}/${each.value}"
  etag   = filemd5("${path.module}/${each.value}")

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

  bucket = each.value.bucket
  key    = each.value.key
  source = each.value.source
  etag   = each.value.etag

  depends_on = [aws_s3_bucket.test_buckets]
}
