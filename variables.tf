variable "aws_region" {
  type        = string
  description = "AWS region to deploy into"
  default     = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = "AMI to use for the instance"
  default     = "ami-0c02fb55956c7d316"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t3.micro"
}

variable "results_bucket_name" {
  type        = string
  description = "S3 bucket for scanner results"
  default = "sentra-results-bucket-ct-us-east1-20250822"
}

# ---------------------------------------------------------------------------
# Scanner behavior. Concurrency. I/O budgets. Output format controls.
# Units: bytes unless otherwise noted. MiB = 1,048,576 bytes.
# ---------------------------------------------------------------------------

# When "1" the scanner writes outputs to the local filesystem at scanner_out_dir.
# This is for local/dev debugging and quick inspection without relying on S3.
# When "0" the scanner behaves normally for infra runs where S3 is the system of record.
# Use "1" if you want to quickly verify parsing and logs on the instance itself.
variable "scanner_dev_mode" {
  type        = string
  default     = "0"  # "1" to write locally
  description = "Toggle local dev output. '1' writes results to scanner_out_dir for easy debugging. '0' keeps outputs strictly in the normal pipeline so S3 stays the source of truth."
}

# Absolute path on the instance where the scanner writes logs and optional local outputs.
# Used when dev mode is enabled. Also useful for storing verbose logs or temporary files.
# Default points to a system log location that is easy to tail and audit.
variable "scanner_out_dir" {
  type        = string
  default     = "/var/log/s3scanner"
  description = "Local output and logs directory on the instance. Used for dev runs and troubleshooting. Keep this on a durable filesystem with enough space for temporary artifacts."
}

# Level of parallelism for the scanner’s work queue.
# Controls ThreadPoolExecutor size and therefore how many S3 objects can be processed at once.
# Higher values increase throughput but also network and CPU use. Tune for the instance size.
variable "scanner_max_workers" {
  type        = number
  default     = 16
  description = "Concurrency for object scanning. Number of worker threads. Raise for faster scans on larger instances. Lower to reduce CPU and network pressure."
}

# Safety valve for raw file reads.
# The scanner samples up to this many bytes from a single non-archive object when searching for signals like emails.
# This keeps very large files from dominating a run. 1 MiB by default.
variable "scanner_sample_bytes" {
  type        = number
  default     = 1048576
  description = "Per-object sample cap for non-archive files. Max bytes to read from any single object. Balance signal detection versus cost. Default 1 MiB."
}

# Cap for reading the outer compressed stream of an archive before extraction completes.
# Prevents pathological archives from consuming excessive time or memory during inspection.
# Works with the per-member and total-archive caps below.
variable "scanner_archive_bytes_limit" {
  type        = number
  default     = 1048576
  description = "Outer-archive read cap. Max bytes read from a compressed archive stream before the scanner stops processing it. Default 1 MiB."
}

# Per inner-file limit inside an archive.
# Each member within a ZIP or TAR.GZ is read up to this many bytes.
# Helps avoid oversized inner files stalling the scan while still extracting useful signals.
variable "scanner_inner_member_read_limit" {
  type        = number
  default     = 131072
  description = "Per-member limit inside an archive. Max bytes read from each inner file. Default 128 KiB."
}

# Total budget for all inner members in a single archive.
# Once the sum of bytes read across members reaches this budget the scanner stops on that archive and moves on.
# This bounds worst-case archives with many large files.
variable "scanner_total_archive_read_budget" {
  type        = number
  default     = 1048576
  description = "Total per-archive budget across all members. When the sum of inner reads reaches this value the archive scan stops. Default 1 MiB."
}

# Backward-compatibility switch for emitting legacy artifacts.
# When "1" the scanner emits legacy JSONL and CSV results alongside the current structured outputs.
# Keep "1" if downstream tools or quick ad-hoc analysis still expect the older formats.
# Set to "0" to reduce duplication and storage.
variable "scanner_write_legacy_outputs" {
  type        = string
  default     = "1"  # "0" disables legacy JSONL/CSV
  description = "Emit legacy JSONL/CSV outputs for compatibility. '1' enables legacy files in addition to current outputs. '0' disables them to save space and simplify pipelines."
}
