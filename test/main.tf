############################################################
# Test buckets + object uploads (zip + unzipped)
# This file intentionally declares NO providers.
# Expect to pass your bucket names via vars.tfvars:
#   test_bucket_names = ["test-bucket-1-...", "test-bucket-2-...", "test-bucket-3-..."]
############################################################

#################################
# Variables (declare elsewhere)
#################################
# variable "test_bucket_names" { type = list(string) }

#################################
# Locals
#################################
locals {
  # Convenient set for for_each on buckets
  test_bucket_set = toset(var.test_bucket_names)
  # ZIP uploads: map bucket_name => absolute path to <bucket>.zip (string)

  zip_src_map = {
    for b in var.test_bucket_names : b => "${path.module}/${b}.zip"
  }

  # Unzipped uploads: flat map of "bucket/filename" => absolute path (string)
  # Built without object-valued items so IDE inspections stay quiet.
  unzipped_src_map = merge([
    for b in var.test_bucket_names : {
      for f in fileset("${path.module}/unzipped_files/${b}", "*") :
      "${b}/${f}" => "${path.module}/unzipped_files/${b}/${f}"
    }
  ]...)

}

#################################
# Buckets (data + logs)
#################################

# Main test data buckets
resource "aws_s3_bucket" "test_buckets" {
  for_each      = local.test_bucket_set
  bucket        = each.key
  force_destroy = true

  tags = {
    purpose = "sentra-scanner-test"
    env     = "test"
  }
}

# Logs buckets named "<bucket>-logs"
resource "aws_s3_bucket" "test_logs" {
  for_each      = local.test_bucket_set
  bucket        = "${each.key}-logs"
  force_destroy = true

  tags = {
    purpose = "sentra-scanner-test-logs"
    env     = "test"
  }
}

############################
# Object uploads
############################

# Upload one ZIP per bucket — key "<bucket>.zip", local "./<bucket>.zip"
resource "aws_s3_object" "zips" {
  for_each = local.zip_src_map

  bucket = each.key
  key    = "${each.key}.zip"
  source = each.value

  # Only re-upload when local file changes
  etag = filemd5(each.value)

  content_type           = "application/octet-stream"
  server_side_encryption = "AES256"

  depends_on = [aws_s3_bucket.test_buckets]
}

# Upload every file under ./unzipped_files/<bucket>/*
# S3 key is the filename under the bucket
resource "aws_s3_object" "unzipped" {
  for_each = local.unzipped_src_map

  # each.key is "bucket/filename"
  bucket = split("/", each.key)[0]
  key    = split("/", each.key)[1]
  source = each.value

  # Only re-upload when local file changes
  etag = filemd5(each.value)

  content_type           = "application/octet-stream"
  server_side_encryption = "AES256"

  depends_on = [aws_s3_bucket.test_buckets]
}

# Block public access on all buckets
resource "aws_s3_bucket_public_access_block" "test_buckets_pab" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_buckets[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "test_logs_pab" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_logs[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Default server-side encryption: AES256 on all buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "test_buckets_sse" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_buckets[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_logs_sse" {
  for_each = local.test_bucket_set
  bucket   = aws_s3_bucket.test_logs[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Access logging from main bucket -> its logs bucket
resource "aws_s3_bucket_logging" "test_buckets_logging" {
  for_each      = local.test_bucket_set
  bucket        = aws_s3_bucket.test_buckets[each.key].id
  target_bucket = aws_s3_bucket.test_logs[each.key].id
  target_prefix = "s3-access/"
}
