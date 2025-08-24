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
