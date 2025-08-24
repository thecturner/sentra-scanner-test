variable "aws_region" {
  default = "us-east-1"
}

variable "ami_id" {
  default = "ami-0c94855ba95c71c99"
}

variable "instance_type" {
  default = "t3.micro"
}

variable "results_bucket_name" {
  default = "sentra-results-bucket-ct-us-east1-20250822"
}

# variables the locals block references
variable "scanner_dev_mode"                  {
  type = string
  default = "0"  # "1" to write locally
}
variable "scanner_out_dir"                   {
  type = string
  default = "/var/log/s3scanner"
}
variable "scanner_max_workers"               {
  type = number
  default = 16
}
variable "scanner_sample_bytes"              {
  type = number
  default = 1048576
}
variable "scanner_archive_bytes_limit"       {
  type = number
  default = 1048576
}
variable "scanner_inner_member_read_limit"   {
  type = number
  default = 131072
}
variable "scanner_total_archive_read_budget" {
  type = number
  default = 1048576
}
variable "scanner_write_legacy_outputs"      {
  type = string
  default = "1"  # "0" disables legacy JSONL/CSV
}
