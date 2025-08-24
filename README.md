# S3 Scanner with Full Archive and File Type Support

## Overview

This Python-based scanner recursively scans **all files** across **all S3 buckets** in your AWS account. It extracts email addresses using regex and supports the most common compression/archive formats.

### Supported File Types

- ✅ Any regular file (regardless of extension)
- ✅ `.zip` — all entries scanned
- ✅ `.gz` — decompress and scan
- ✅ `.tar.gz` / `.tgz` — extract and scan every file inside the archive

---


## 🔍 Features

### 1. Non-Data Filetype Filtering
- Skips `.mp4`, `.png`, `.jpg`, `.mkv`, etc.
- Still stores metadata for skipped files.

### 2. File Prioritization
- Prioritized filetypes: `.csv`, `.log`, `.json`, `.xml`, `.sql`
- Media formats are deprioritized but not skipped.

### 3. Manifest-Based Deduplication
- A manifest file in the `results` bucket keeps track of previously scanned files.
- Prevents rescanning unchanged objects.

### 4. Threaded Scanning
- Uses `ThreadPoolExecutor` to concurrently scan objects in multiple buckets.

### 5. Metadata Separation
- `scan_results.json`: email detection results.
- `metadata.json`: S3 object metadata (key, size, last modified, etc.)

---

## 🧪 How It Works

1. Iterates over all S3 buckets (excluding the results bucket).
2. Lists all objects using pagination.
3. Filters and prioritizes files based on extensions.
4. Extracts archives and scans contents line-by-line.
5. Detects emails using regex.
6. Uploads results and metadata to your designated results bucket.
7. Updates manifest to skip already scanned files in future runs.

---

## Example Output

```json
{
  "bucket-name": {
    "data.csv": ["support@domain.com"],
    "archive.zip": ["zipper@zmail.io"],
    "file.tar.gz": ["tarball@archive.org"]
  }
}
```

---

## Requirements

### IAM Permissions

Ensure your EC2 instance has a role that allows:

- `s3:ListAllMyBuckets`
- `s3:ListBucket`
- `s3:GetObject`
- `s3:PutObject`

---

## How to Use
NOTE:Terraform uses the get_my_ip.sh script to determine your IP dynamically at plan/apply time:

#!/bin/bash
curl -s ifconfig.me | jq -R '{ ip: . }'


This ensures that only your IP has access to the EC2 instance via SSH.

```bash
# 1. SSH into your EC2 instance 
ssh -i ~/.ssh/id_ed25519 ec2-user@<ec2_public_ip>
# Replace <ec2_public_ip> with the output from Terraform or AWS Console.

# 2. Install dependencies
sudo apt update && sudo apt install -y python3-pip
pip3 install boto3

# 3. Run the scanner
python3 scanner_full.py
```

The results will be available in your specified S3 bucket.

---

This scanner is suitable for automated security audits or compliance scans across varied S3 content types, including compressed datasets.


---

## 🧠 Key Design Choices and Justifications

### Compute Infrastructure: EC2 Instance
- Chosen for flexibility, ease of debugging, and full Python environment access.
- Better suited than Lambda for large, memory-intensive operations like reading archive contents.
- Avoids Lambda timeout issues and package size limits.

### File Processing Algorithm
- Uses regular expressions to match email patterns: simple, reliable, and language-agnostic.
- Handles all file types uniformly and attempts decoding for all unknown types.
- Gzip, TAR.GZ, and ZIP handled via Python standard libraries (`gzip`, `tarfile`, `zipfile`) for in-memory extraction.

### Communication with Sentra’s SaaS (Simulated)
- Results are written back to a designated S3 bucket (`sentra-results-bucket`) as a JSON file.
- This assumes Sentra SaaS would periodically read or receive notifications from the results bucket.

---

This setup ensures scalable, cost-effective, and easily extendable scans across your entire S3 landscape.
