#!/usr/bin/env python3
"""
Minimal S3 Scanner Example
--------------------------
This script connects to AWS S3 using boto3, scans all accessible buckets
(except the designated results bucket), and looks for email addresses in files.

It then writes one consolidated JSON file ("full_scan_results.json")
into the specified RESULTS_BUCKET, shaped like:

{
  "bucket-name": {
    "object-key.txt": ["email1@example.com", "email2@example.com"]
  }
}

Limitations:
- Only scans plain file content (no archive unpacking).
- Uses a simple regex to find email addresses.
- Loads entire objects into memory (not efficient for very large files).
"""

import boto3, re, json, sys, os

# -------------------------
# 1. Configuration
# -------------------------

# Simple regex pattern to match email addresses.
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# -------------------------
# 2. Helpers
# -------------------------

def extract_emails_from_bytes(data: bytes):
    """
    Try to decode a blob of bytes into text and extract email addresses.
    Returns a sorted list of unique emails.
    """
    try:
        # Preferred: UTF-8 decode
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        # Fallback: Latin-1 if UTF-8 fails
        text = data.decode("latin-1", errors="ignore")
    return sorted(set(EMAIL_REGEX.findall(text)))


def scan_object(s3, bucket, key):
    """
    Download an S3 object and scan its contents for emails.
    Returns a list of found email addresses.
    """
    # Bytearray to hold data
    data = bytearray()

    # Writer object with a 'write' method to satisfy download_fileobj
    class Writer:
        def write(self, chunk): data.extend(chunk)

    try:
        # Stream the object into our bytearray
        s3.download_fileobj(bucket, key, Writer())
        return extract_emails_from_bytes(bytes(data))
    except Exception as e:
        print(f"error on {bucket}/{key}: {e}", file=sys.stderr)
        return []


# -------------------------
# 3. Main
# -------------------------

def main():
    # AWS region (default to us-east-1 if not set)
    region = os.environ.get("AWS_REGION", "us-east-1")

    # Bucket to store results in (must be set in env)
    results_bucket = os.environ.get("RESULTS_BUCKET")
    if not results_bucket:
        print("RESULTS_BUCKET env var required", file=sys.stderr)
        sys.exit(1)

    # Create boto3 S3 client in given region
    s3 = boto3.client("s3", region_name=region)

    # Our aggregated results: dict of bucket → key → list of emails
    results = {}

    # Get list of all buckets accessible to these credentials
    for b in [b["Name"] for b in s3.list_buckets()["Buckets"]]:
        # Skip the results bucket to avoid scanning our own output
        if b == results_bucket:
            continue

        bucket_results = {}

        # Use paginator so we can handle buckets with many objects
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=b):
            for obj in page.get("Contents", []):
                key = obj["Key"]

                # Scan the object
                emails = scan_object(s3, b, key)
                if emails:
                    bucket_results[key] = emails

        # Only record non-empty buckets
        if bucket_results:
            results[b] = bucket_results

    # Serialize results to JSON
    body = json.dumps(results, indent=2)

    # Write results back to our results bucket
    s3.put_object(
        Bucket=results_bucket,
        Key="full_scan_results.json",
        Body=body.encode("utf-8"),
        ContentType="application/json"
    )

    print("Uploaded full_scan_results.json")

# Entry point
if __name__ == "__main__":
    main()
