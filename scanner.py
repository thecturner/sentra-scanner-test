#!/usr/bin/env python3
"""
S3 Scanner with "dev mode" and results shaped like:

{
  "<bucket_name>": {
    "<object_key_or_filename>": [
      "<finding_1>", "<finding_2>", "..."
    ]
  },
  "..."
}

Key points.
  . Scan ALL buckets the current identity can access.
  . Use concurrency.
  . Maintain a manifest to avoid rescanning unchanged objects.
  . Sample bytes from objects for lightweight inspection.
  . Peek into small archives and scan their contents.
  . Optionally write legacy outputs (JSONL + CSV) for backward compatibility.

- Main results file:
  . One JSON file aggregating findings per bucket->object per schema above.
  . In dev mode, written to a local directory.
  . In non-dev mode, written to S3.

"Findings" are simple pattern matches extracted from sampled bytes and small archives:
  . Email addresses.
  . IPv4 addresses. (commented out)
  . AWS Access Key IDs (AKIA/ASIAxxxxxxxxxxxxxxxx). (commented out)

You can control limits and behavior via CLI flags and env vars.
"""

import argparse
import concurrent.futures as futures
import contextlib
import csv
import datetime as dt
import io
import json
import os
import sys
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Set

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, BotoCoreError

# ---------------------------
# Defaults and configuration
# ---------------------------

DEFAULT_MAX_WORKERS = int(os.environ.get("SCANNER_MAX_WORKERS", "16"))
DEFAULT_SAMPLE_BYTES = int(os.environ.get("SCANNER_SAMPLE_BYTES", "1048576"))  # 1 MiB from object head
DEFAULT_ARCHIVE_BYTES_LIMIT = int(os.environ.get("SCANNER_ARCHIVE_BYTES_LIMIT", str(DEFAULT_SAMPLE_BYTES)))  # download whole archive if <= this size
DEFAULT_INNER_MEMBER_READ_LIMIT = int(os.environ.get("SCANNER_INNER_MEMBER_READ_LIMIT", "131072"))  # 128 KiB per inner file
DEFAULT_TOTAL_ARCHIVE_READ_BUDGET = int(os.environ.get("SCANNER_TOTAL_ARCHIVE_READ_BUDGET", "1048576"))  # 1 MiB total per archive

# Write legacy outputs (JSONL + CSV) in addition to the new results JSON
WRITE_LEGACY_OUTPUTS = os.environ.get("SCANNER_WRITE_LEGACY_OUTPUTS", "1") not in {"0", "false", "False", ""}

RESULTS_BUCKET_ENV = os.environ.get("RESULTS_BUCKET", "")
AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

# Filetype preferences
DATA_EXTENSIONS = {
    ".csv", ".log", ".json", ".jsonl", ".xml", ".sql", ".parquet", ".ndjson", ".txt"
}
COMMON_MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".mov", ".avi", ".mp3", ".flac", ".jpg", ".jpeg", ".png", ".gif", ".webp"
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tgz", ".gz"}

MANIFEST_KEY = "scanner/manifest.json"
RESULTS_PREFIX = "scanner/results"
METADATA_PREFIX = "scanner/metadata"
FINAL_RESULTS_BASENAME = "full_scan_results.json"  # main new schema file name

# ---------------------------
# Utilities
# ---------------------------

def utcnow_iso():
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def sha256_of_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def ext_of_key(key: str) -> str:
    p = Path(key)
    # handle .tar.gz / .tgz specially
    low = key.lower()
    if low.endswith(".tar.gz"):
        return ".tar.gz"
    if low.endswith(".tgz"):
        return ".tgz"
    return p.suffix.lower()

def is_archive_key(key: str) -> bool:
    ext = ext_of_key(key)
    return ext in {".zip", ".tar", ".tar.gz", ".tgz", ".gz"}

def safe_int(x, default=None):
    try:
        return int(x)
    except Exception:
        return default

def unique_preserving_order(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

# ---------------------------
# Pattern finding
# ---------------------------

import re

EMAIL_RE = re.compile(rb"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
AWS_KEY_RE = re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _valid_ipv4(match_bytes: bytes) -> bool:
    try:
        parts = match_bytes.decode("ascii").split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True
    except Exception:
        return False

def extract_findings_from_bytes(data: bytes, budget: int) -> List[str]:
    """
    Extract findings from a chunk of bytes, limited by 'budget' to avoid runaway matches.
    """
    findings: List[str] = []
    if not data:
        return findings

    # Email addresses
    for m in EMAIL_RE.finditer(data):
        findings.append(m.group(0).decode("utf-8", errors="ignore"))
        if len(findings) >= budget:
            return unique_preserving_order(findings)

    # AWS Access Key IDs
    #for m in AWS_KEY_RE.finditer(data):
    #    findings.append(m.group(0).decode("ascii", errors="ignore"))
    #    if len(findings) >= budget:
    #        return unique_preserving_order(findings)

    # IPv4 addresses (filter invalid)
    #for m in IPV4_RE.finditer(data):
    #    mb = m.group(0)
    #    if _valid_ipv4(mb):
    #        findings.append(mb.decode("ascii"))
    #        if len(findings) >= budget:
    #            return unique_preserving_order(findings)

    return unique_preserving_order(findings)

# ---------------------------
# Output Writers
# ---------------------------

class OutputSink:
    """Abstracts writing results and manifest either to S3 or local folder. Also supports legacy outputs."""

    # --- new schema ---
    def write_results_tree(self, results_tree: dict):
        raise NotImplementedError

    # --- manifest ---
    def write_manifest(self, manifest: dict):
        raise NotImplementedError

    def read_manifest(self) -> dict:
        raise NotImplementedError

    # --- legacy outputs (optional) ---
    def open_legacy_results_files(self) -> Tuple[contextlib.AbstractContextManager, contextlib.AbstractContextManager]:
        """
        Returns context managers yielding (jsonl_fp, metadata_csv_writer)
        jsonl_fp: a text file-like handle to write JSONL records
        metadata_csv_writer: csv.DictWriter already primed with header
        """
        raise NotImplementedError

    def target_str(self) -> str:
        raise NotImplementedError


class S3Sink(OutputSink):
    def __init__(self, s3_client, bucket: str):
        self.s3 = s3_client
        self.bucket = bucket

        timestamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        # Legacy outputs
        self.legacy_jsonl_key = f"{RESULTS_PREFIX}/objects_{timestamp}.jsonl"
        self.metadata_key = f"{METADATA_PREFIX}/object_metadata_{timestamp}.csv"
        # New schema file (stable name and timestamped copy)
        self.final_results_key = f"{RESULTS_PREFIX}/{FINAL_RESULTS_BASENAME}"
        self.final_results_key_ts = f"{RESULTS_PREFIX}/{timestamp}_{FINAL_RESULTS_BASENAME}"

    # --- new schema ---
    def write_results_tree(self, results_tree: dict):
        body = json.dumps(results_tree, indent=2).encode("utf-8")
        # Write stable name and timestamped name
        self.s3.put_object(Bucket=self.bucket, Key=self.final_results_key, Body=body, ContentType="application/json")
        self.s3.put_object(Bucket=self.bucket, Key=self.final_results_key_ts, Body=body, ContentType="application/json")

    # --- manifest ---
    def write_manifest(self, manifest: dict):
        body = json.dumps(manifest, indent=2).encode("utf-8")
        self.s3.put_object(Bucket=self.bucket, Key=MANIFEST_KEY, Body=body, ContentType="application/json")

    def read_manifest(self) -> dict:
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=MANIFEST_KEY)
            return json.loads(resp["Body"].read().decode("utf-8"))
        except self.s3.exceptions.NoSuchKey:
            return {}
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                return {}
            raise

    # --- legacy outputs (optional) ---
    @contextlib.contextmanager
    def open_legacy_results_files(self):
        jsonl_buf = io.StringIO()
        csv_buf = io.StringIO()
        csv_writer = csv.DictWriter(csv_buf, fieldnames=[
            "bucket","key","size","last_modified","storage_class","etag","content_type","sse","glacier","archive","priority"
        ])
        csv_writer.writeheader()
        try:
            yield jsonl_buf, csv_writer
        finally:
            # Upload only if asked to write legacy outputs
            if WRITE_LEGACY_OUTPUTS:
                self.s3.put_object(Bucket=self.bucket, Key=self.legacy_jsonl_key, Body=jsonl_buf.getvalue().encode("utf-8"), ContentType="application/jsonl")
                self.s3.put_object(Bucket=self.bucket, Key=self.metadata_key, Body=csv_buf.getvalue().encode("utf-8"), ContentType="text/csv")

    def target_str(self) -> str:
        return f"s3://{self.bucket}/{RESULTS_PREFIX}"


class LocalSink(OutputSink):
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        # Legacy outputs
        self.legacy_jsonl_path = self.out_dir / f"objects_{timestamp}.jsonl"
        self.metadata_path = self.out_dir / f"object_metadata_{timestamp}.csv"
        # New schema files
        self.final_results_path = self.out_dir / FINAL_RESULTS_BASENAME
        self.final_results_path_ts = self.out_dir / f"{timestamp}_{FINAL_RESULTS_BASENAME}"
        # Manifest
        self.manifest_path = self.out_dir / "manifest.json"

    # --- new schema ---
    def write_results_tree(self, results_tree: dict):
        text = json.dumps(results_tree, indent=2)
        self.final_results_path.write_text(text)
        self.final_results_path_ts.write_text(text)

    # --- manifest ---
    def write_manifest(self, manifest: dict):
        self.manifest_path.write_text(json.dumps(manifest, indent=2))

    def read_manifest(self) -> dict:
        if self.manifest_path.exists():
            return json.loads(self.manifest_path.read_text())
        return {}

    # --- legacy outputs (optional) ---
    @contextlib.contextmanager
    def open_legacy_results_files(self):
        with self.legacy_jsonl_path.open("w", encoding="utf-8") as jf, self.metadata_path.open("w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=[
                "bucket","key","size","last_modified","storage_class","etag","content_type","sse","glacier","archive","priority"
            ])
            writer.writeheader()
            yield jf, writer

    def target_str(self) -> str:
        return str(self.out_dir)

# ---------------------------
# Scanner
# ---------------------------

class S3Scanner:
    def __init__(
        self,
        s3_client,
        sink: OutputSink,
        max_workers: int = DEFAULT_MAX_WORKERS,
        sample_bytes: int = DEFAULT_SAMPLE_BYTES,
        archive_bytes_limit: int = DEFAULT_ARCHIVE_BYTES_LIMIT,
        inner_member_read_limit: int = DEFAULT_INNER_MEMBER_READ_LIMIT,
        total_archive_read_budget: int = DEFAULT_TOTAL_ARCHIVE_READ_BUDGET,
        skip_bucket: Optional[str] = None,
    ):
        self.s3 = s3_client
        self.sink = sink
        self.sample_bytes = sample_bytes
        self.archive_bytes_limit = archive_bytes_limit
        self.inner_member_read_limit = inner_member_read_limit
        self.total_archive_read_budget = total_archive_read_budget
        self.skip_bucket = skip_bucket
        self.max_workers = max_workers

        self._manifest_lock = threading.Lock()
        self.manifest = self.sink.read_manifest() or {}
        self.manifest.setdefault("version", 1)
        self.manifest.setdefault("objects", {})  # key: f"{bucket}/{key}" -> {"etag":..., "size":..., "last_modified":...}

        # Results aggregation (new schema)
        self._results_lock = threading.Lock()
        self.results_tree: Dict[str, Dict[str, List[str]]] = {}

    # ----- listing -----

    def list_buckets(self) -> List[str]:
        resp = self.s3.list_buckets()
        names = [b["Name"] for b in resp.get("Buckets", [])]
        if self.skip_bucket and self.skip_bucket in names:
            names = [n for n in names if n != self.skip_bucket]
        return names

    def list_objects(self, bucket: str) -> Iterable[dict]:
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                yield obj

    # ----- manifest checks -----

    def _already_scanned(self, bucket: str, key: str, size: int, etag: str, last_modified: str) -> bool:
        mkey = f"{bucket}/{key}"
        entry = self.manifest["objects"].get(mkey)
        if not entry:
            return False
        return (
            entry.get("etag") == etag
            and safe_int(entry.get("size")) == size
            and entry.get("last_modified") == last_modified
        )

    def _update_manifest(self, bucket: str, key: str, size: int, etag: str, last_modified: str):
        mkey = f"{bucket}/{key}"
        with self._manifest_lock:
            self.manifest["objects"][mkey] = {
                "etag": etag,
                "size": size,
                "last_modified": last_modified,
                "updated_at": utcnow_iso(),
            }

    # ----- helpers -----

    def _priority_tag(self, key: str) -> str:
        ext = ext_of_key(key)
        if ext in DATA_EXTENSIONS:
            return "data"
        if ext in COMMON_MEDIA_EXTENSIONS:
            return "media"
        if is_archive_key(key):
            return "archive"
        return "other"

    def head_object(self, bucket: str, key: str) -> dict:
        try:
            return self.s3.head_object(Bucket=bucket, Key=key)
        except ClientError as e:
            return {"Error": str(e)}

    def _get_object_range(self, bucket: str, key: str, rng: Optional[str]) -> Optional[bytes]:
        try:
            if rng:
                resp = self.s3.get_object(Bucket=bucket, Key=key, Range=rng)
            else:
                resp = self.s3.get_object(Bucket=bucket, Key=key)
            return resp["Body"].read()
        except ClientError:
            return None

    def sample_bytes_from_object(self, bucket: str, key: str, size: int) -> Optional[bytes]:
        if self.sample_bytes <= 0:
            return None
        rng_end = min(size - 1, self.sample_bytes - 1) if size > 0 else self.sample_bytes - 1
        if rng_end < 0:
            return None
        return self._get_object_range(bucket, key, f"bytes=0-{rng_end}")

    # ----- archive scanning -----

    def scan_small_archive_for_findings(self, bucket: str, key: str, size: int) -> List[str]:
        """
        If the object looks like an archive and its total size <= archive_bytes_limit,
        download it whole and scan inside members (up to budgets).
        """
        if not is_archive_key(key):
            return []
        if size <= 0 or size > self.archive_bytes_limit:
            return []

        blob = self._get_object_range(bucket, key, None)
        if not blob:
            return []

        findings: List[str] = []
        budget_remaining = self.total_archive_read_budget

        ext = ext_of_key(key)
        if ext == ".zip":
            import zipfile
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    for zi in zf.infolist():
                        if zi.is_dir():
                            continue
                        if budget_remaining <= 0:
                            break
                        to_read = min(self.inner_member_read_limit, budget_remaining, zi.file_size)
                        with zf.open(zi, "r") as zfh:
                            chunk = zfh.read(to_read)
                        budget_remaining -= len(chunk)
                        findings.extend(extract_findings_from_bytes(chunk, 500))
            except Exception:
                return unique_preserving_order(findings)

        elif ext in {".tar", ".tar.gz", ".tgz"}:
            import tarfile
            try:
                mode = "r:*"
                with tarfile.open(fileobj=io.BytesIO(blob), mode=mode) as tf:
                    for ti in tf.getmembers():
                        if not ti.isfile():
                            continue
                        if budget_remaining <= 0:
                            break
                        to_read = min(self.inner_member_read_limit, budget_remaining, ti.size if ti.size is not None else self.inner_member_read_limit)
                        f = tf.extractfile(ti)
                        if not f:
                            continue
                        chunk = f.read(to_read)
                        budget_remaining -= len(chunk)
                        findings.extend(extract_findings_from_bytes(chunk, 500))
            except Exception:
                return unique_preserving_order(findings)

        elif ext == ".gz":
            # Single-file gzip
            try:
                import gzip as _gzip
                with _gzip.GzipFile(fileobj=io.BytesIO(blob)) as gf:
                    to_read = min(self.total_archive_read_budget, self.inner_member_read_limit)
                    chunk = gf.read(to_read)
                    findings.extend(extract_findings_from_bytes(chunk, 500))
            except Exception:
                pass

        return unique_preserving_order(findings)

    # ----- scanning -----

    def scan_object(self, bucket: str, obj: dict) -> Tuple[Optional[dict], Optional[dict], Optional[List[str]]]:
        """
        Returns:
          record (legacy JSONL per-object dict) or None,
          meta_row (legacy CSV row) or None,
          findings (list for the new schema) or None
        """
        key = obj["Key"]
        size = int(obj.get("Size", 0))
        etag = obj.get("ETag", "").strip('"')
        lm = obj.get("LastModified")
        if hasattr(lm, "isoformat"):
            last_modified = lm.replace(tzinfo=dt.timezone.utc).isoformat()
        else:
            last_modified = str(lm)

        # Consult manifest
        if self._already_scanned(bucket, key, size, etag, last_modified):
            # No new findings added for unchanged objects
            return None, None, None

        head = self.head_object(bucket, key)
        content_type = head.get("ContentType")
        sse = head.get("ServerSideEncryption")
        storage_class = head.get("StorageClass") or obj.get("StorageClass")
        glacier = storage_class in {"GLACIER", "DEEP_ARCHIVE", "GLACIER_IR"}
        archive = is_archive_key(key)
        priority = self._priority_tag(key)

        # Findings
        findings: List[str] = []

        # 1) For small archives, read and scan inside members
        if archive:
            findings.extend(self.scan_small_archive_for_findings(bucket, key, size))

        # 2) Sample head bytes of the object itself and scan
        sample_blob = self.sample_bytes_from_object(bucket, key, size)
        sample_hash = None
        sample_len = None
        if sample_blob is not None:
            sample_len = len(sample_blob)
            sample_hash = sha256_of_bytes(sample_blob)
            findings.extend(extract_findings_from_bytes(sample_blob, 500))

        findings = unique_preserving_order(findings)

        # Legacy record + metadata row (only if we write legacy outputs)
        record = None
        meta_row = None
        if WRITE_LEGACY_OUTPUTS:
            record = {
                "bucket": bucket,
                "key": key,
                "size": size,
                "etag": etag,
                "last_modified": last_modified,
                "storage_class": storage_class,
                "content_type": content_type,
                "sse": sse,
                "glacier": glacier,
                "archive": archive,
                "priority": priority,
                "sample": {
                    "sha256": sample_hash,
                    "bytes": sample_len,
                },
                "findings": findings,
                "scanned_at": utcnow_iso(),
            }
            meta_row = {
                "bucket": bucket,
                "key": key,
                "size": size,
                "last_modified": last_modified,
                "storage_class": storage_class,
                "etag": etag,
                "content_type": content_type,
                "sse": sse,
                "glacier": glacier,
                "archive": archive,
                "priority": priority,
            }

        # Update manifest
        self._update_manifest(bucket, key, size, etag, last_modified)

        # Update results tree (only store object if there are findings; keep empty bucket map otherwise)
        if findings:
            with self._results_lock:
                bmap = self.results_tree.setdefault(bucket, {})
                bmap[key] = findings
        else:
            # Ensure bucket exists in results (empty dict) to mirror sample shape
            with self._results_lock:
                self.results_tree.setdefault(bucket, {})

        return record, meta_row, findings

    # ----- run -----

    def run(self) -> Tuple[int, int, int]:
        buckets = self.list_buckets()
        total_objects = 0
        scanned_objects = 0
        errors = 0

        with self.sink.open_legacy_results_files() as (jsonl_fp, metadata_csv):
            writer_lock = threading.Lock()

            def handle_result(res):
                nonlocal scanned_objects, errors
                try:
                    record, meta, findings = res
                    if WRITE_LEGACY_OUTPUTS and record is not None:
                        with writer_lock:
                            jsonl_fp.write(json.dumps(record, ensure_ascii=False) + "\n")
                            if meta is not None:
                                metadata_csv.writerow(meta)
                    if record is not None:
                        scanned_objects += 1
                except Exception:
                    errors += 1

            with futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                future_list = []
                for b in buckets:
                    try:
                        for obj in self.list_objects(b):
                            total_objects += 1
                            future_list.append(pool.submit(self.scan_object, b, obj))
                    except ClientError:
                        errors += 1
                        continue

                for f in futures.as_completed(future_list):
                    try:
                        handle_result(f.result())
                    except Exception:
                        errors += 1

        # Persist manifest and results tree
        self.sink.write_manifest(self.manifest)
        self.sink.write_results_tree(self.results_tree)

        return total_objects, scanned_objects, errors

# ---------------------------
# CLI
# ---------------------------

def build_boto3_client():
    session_kwargs = {}
    if AWS_REGION:
        session_kwargs["region_name"] = AWS_REGION
    session = boto3.session.Session(**session_kwargs)
    return session.client("s3")

def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Scan all S3 buckets and write results either to S3 or a local folder.")
    ap.add_argument("--dev", action="store_true", help="Enable dev mode. Write outputs to a local folder instead of S3.")
    ap.add_argument("--out", type=str, default="./scanner_out", help="Local output directory for dev mode.")
    ap.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Thread pool size.")
    ap.add_argument("--sample-bytes", type=int, default=DEFAULT_SAMPLE_BYTES, help="Bytes to sample from start of object for hashing and pattern scan. 0 to disable.")
    ap.add_argument("--archive-bytes-limit", type=int, default=DEFAULT_ARCHIVE_BYTES_LIMIT, help="If an archive object is <= this size, download whole archive and scan inside members.")
    ap.add_argument("--inner-member-read-limit", type=int, default=DEFAULT_INNER_MEMBER_READ_LIMIT, help="Per inner file read limit within an archive.")
    ap.add_argument("--total-archive-read-budget", type=int, default=DEFAULT_TOTAL_ARCHIVE_READ_BUDGET, help="Total bytes to read across inner files per archive.")
    ap.add_argument("--results-bucket", type=str, default=RESULTS_BUCKET_ENV, help="Results bucket for non-dev mode.")
    return ap.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)
    s3 = build_boto3_client()

    if args.dev:
        sink = LocalSink(Path(args.out))
        skip_bucket = None
    else:
        bucket = args.results_bucket or os.environ.get("RESULTS_BUCKET", "")
        if not bucket:
            print("RESULTS_BUCKET or --results-bucket is required for non-dev mode.", file=sys.stderr)
            sys.exit(2)
        sink = S3Sink(s3, bucket)
        skip_bucket = bucket  # do not scan our own results bucket

    scanner = S3Scanner(
        s3_client=s3,
        sink=sink,
        max_workers=args.max_workers,
        sample_bytes=args.sample_bytes,
        archive_bytes_limit=args.archive_bytes_limit,
        inner_member_read_limit=args.inner_member_read_limit,
        total_archive_read_budget=args.total_archive_read_budget,
        skip_bucket=skip_bucket
    )

    print(f"[{utcnow_iso()}] Starting scan. Output -> {sink.target_str()}")
    total, scanned, errors = scanner.run()
    print(f"[{utcnow_iso()}] Done. total_objects={total} scanned={scanned} errors={errors}")
    if isinstance(sink, LocalSink):
        print(f"Main results JSON: {sink.final_results_path}")
        if WRITE_LEGACY_OUTPUTS:
            print(f"Legacy outputs: {sink.legacy_jsonl_path}, {sink.metadata_path}")
    else:
        print("Main results JSON written to S3. See full_scan_results.json and the timestamped copy under scanner/results/.")
        if WRITE_LEGACY_OUTPUTS:
            print("Legacy JSONL and CSV written under scanner/results/ and scanner/metadata/ respectively.")

if __name__ == "__main__":
    main()
