#!/usr/bin/env python3

import boto3
import os
import re
import json
import tempfile
import zipfile
import tarfile
import gzip
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
results_bucket = os.environ.get("RESULTS_BUCKET", "sentra-results-bucket-ct-us-east1-20250822")

# Filetype priorities
DATA_FILETYPES = {".csv", ".log", ".json", ".xml", ".sql"}
MEDIA_FILETYPES = {".mp4", ".mp3", ".jpg", ".jpeg", ".png", ".mkv"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz"}

# Compile regex for email
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

# Manifest file key
MANIFEST_KEY = "results/manifest.json"

def load_manifest():
    try:
        response = s3.get_object(Bucket=results_bucket, Key=MANIFEST_KEY)
        return json.loads(response["Body"].read())
    except ClientError:
        return {}

def save_manifest(manifest):
    s3.put_object(Bucket=results_bucket, Key=MANIFEST_KEY,
                  Body=json.dumps(manifest, indent=2))

def list_all_buckets():
    return [bucket["Name"] for bucket in s3.list_buckets()["Buckets"]]

def list_objects(bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            yield obj

def download_file(bucket, key):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    s3.download_fileobj(bucket, key, tmp)
    tmp.close()
    return tmp.name

def extract_archive(file_path):
    extracted_files = []
    tmp_dir = tempfile.mkdtemp()
    ext = Path(file_path).suffix.lower()

    try:
        if ext == ".zip":
            with zipfile.ZipFile(file_path, "r") as z:
                z.extractall(tmp_dir)
                extracted_files = [os.path.join(tmp_dir, f) for f in z.namelist()]
        elif ext in [".tar", ".tgz"]:
            with tarfile.open(file_path, "r:*") as t:
                t.extractall(tmp_dir)
                extracted_files = [os.path.join(tmp_dir, f.name) for f in t.getmembers() if f.isfile()]
        elif ext == ".gz":
            out_file = os.path.join(tmp_dir, Path(file_path).stem)
            with gzip.open(file_path, "rb") as f_in, open(out_file, "wb") as f_out:
                f_out.write(f_in.read())
                extracted_files = [out_file]
    except Exception as e:
        print(f"Error processing archive: {e}")
        pass
    return extracted_files

def scan_file(file_path):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                findings.extend(EMAIL_REGEX.findall(line))
    except Exception as e:
        print(f"Error processing archive: {e}")
        pass
    return findings

def scan_object(bucket, obj, manifest):
    key = obj["Key"]
    last_modified = obj["LastModified"].isoformat()
    ext = Path(key).suffix.lower()

    # skip unscannable media
    if ext in MEDIA_FILETYPES:
        priority = "low"
    elif ext in DATA_FILETYPES:
        priority = "high"
    else:
        priority = "medium"

    # skip unchanged files
    if manifest.get(f"{bucket}/{key}") == last_modified:
        return

    temp_file = download_file(bucket, key)
    files_to_scan = [temp_file]

    if ext in ARCHIVE_EXTENSIONS:
        files_to_scan = extract_archive(temp_file)

    all_findings = []
    for path in files_to_scan:
        emails = scan_file(path)
        if emails:
            all_findings.append({"file": path, "emails": list(set(emails))})

    # Save results
    s3.put_object(Bucket=results_bucket,
                  Key=f"results/{bucket}/scan_results.json",
                  Body=json.dumps(all_findings, indent=2))

    # Save metadata
    s3.put_object(Bucket=results_bucket,
                  Key=f"results/{bucket}/metadata.json",
                  Body=json.dumps(obj, default=str, indent=2))

    manifest[f"{bucket}/{key}"] = last_modified

def main():
    manifest = load_manifest()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for bucket in list_all_buckets():
            if bucket == results_bucket:
                continue
            for obj in list_objects(bucket):
                futures.append(executor.submit(scan_object, bucket, obj, manifest))

        for f in futures:
            f.result()

    save_manifest(manifest)

if __name__ == "__main__":
    main()
