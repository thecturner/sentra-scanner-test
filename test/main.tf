# Test buckets module - clean for_each and no cross-resource references
# This file intentionally contains NO provider or variable blocks.
# Expect variable `test_bucket_names` to be defined once in test/variables.tf.

locals {
  # Plan-time set used for for_each
  test_bucket_set = toset(var.test_bucket_names)
}

# One CMK for all test buckets
resource "aws_kms_key" "test_buckets" {
  description             = "KMS for test buckets"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

# Main buckets
resource "aws_s3_bucket" "test_buckets" {
  for_each      = local.test_bucket_set
  bucket        = each.key
  force_destroy = true
  tags = {
    Purpose = "test"
  }
}

# This bucket is already the target for access logs from the primary buckets.
# We route its logs to a central sink in a later hardening step.
# Logs buckets (derived name: <main>-logs)
#tfsec:ignore:AVD-AWS-0089
resource "aws_s3_bucket" "test_logs" {
  for_each      = local.test_bucket_set
  bucket        = "${each.key}-logs"
  force_destroy = true
  tags = {
    Purpose = "test-logs"
  }
}

# Public Access Block on main buckets
resource "aws_s3_bucket_public_access_block" "test_buckets_pab" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_buckets[each.key].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Public Access Block on logs buckets
resource "aws_s3_bucket_public_access_block" "test_logs_pab" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_logs[each.key].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Versioning on main buckets
resource "aws_s3_bucket_versioning" "test_buckets_ver" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_buckets[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Versioning on logs buckets
resource "aws_s3_bucket_versioning" "test_logs_ver" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_logs[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-KMS on main buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "test_buckets_sse" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_buckets[each.key].id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.test_buckets.arn
    }
  }
}

# SSE-KMS on logs buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "test_logs_sse" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_logs[each.key].id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.test_buckets.arn
    }
  }
}

# Access logging from main buckets to their matching logs buckets
resource "aws_s3_bucket_logging" "test_buckets_logging" {
  for_each      = local.test_bucket_set
  bucket        = aws_s3_bucket.test_buckets[each.key].id
  target_bucket = aws_s3_bucket.test_logs[each.key].id
  target_prefix = "s3-access/"
}
