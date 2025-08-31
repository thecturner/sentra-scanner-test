#!/usr/bin/env python3
"""
S3 Object Scanner with Archive Support and Dev Mode.

Features.
- Scans objects in specified S3 buckets and prefixes.
- Optional archive extraction for .zip .tar .tgz .gz to scan inner files.
- Skips rescanning unchanged objects using a manifest ETag + Size + LastModified.
- Prioritizes data filetypes .csv .log .json .xml .sql but scans all files.
- Skips common large media types early during content scanning to save time.
- Concurrency via ThreadPoolExecutor.
- Stores object metadata separately from findings.
- Normal mode. writes results and manifest to an S3 results bucket.
- Dev mode. writes results and manifest to a local folder.

Usage examples.
  python scanner.py --buckets my-bucket-1,my-bucket-2 --prefix data/ --results-bucket my-results-bucket
  python scanner.py --dev --dev-output ./scan_output --buckets my-bucket

Environment variables can also configure defaults.
"""

import argparse
import concurrent.futures
import contextlib
import fnmatch
import gzip
import io
import json
import os
import queue
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# -----------------------------
# Defaults and configuration
# -----------------------------

DEFAULT_PRIORITY_EXTS = {".csv", ".log", ".json", ".xml", ".sql"}
SKIP_EARLY_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".webp", ".mp3", ".wav", ".flac"}
ARCHIVE_EXTS = {".zip", ".tar", ".tgz", ".gz"}  # gz assumed single-member gzip

RESULTS_BUCKET_ENV = os.environ.get("RESULTS_BUCKET", "")
AWS_REGION_ENV = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
CONCURRENCY_ENV = int(os.environ.get("SCANNER_CONCURRENCY", "8"))
MANIFEST_KEY_ENV = os.environ.get("SCANNER_MANIFEST_KEY", "scanner/manifest.json")
RESULTS_PREFIX_ENV = os.environ.get("SCANNER_RESULTS_PREFIX", "scanner/results")

# -----------------------------
# Data classes
# -----------------------------

@dataclass
class ObjectRef:
    bucket: str
    key: str
    etag: Optional[str]
    size: int
    last_modified: Optional[str]  # ISO format

@dataclass
class ScanFinding:
    bucket: str
    key: str
    path_in_archive: Optional[str]
    pattern: str
    match: str
    start: int
    end: int
    context: str

@dataclass
class ObjectMetadata:
    bucket: str
    key: str
    etag: Optional[str]
    size: int
    last_modified: Optional[str]
    sha256: Optional[str]
    content_type: Optional[str]
    scanned_bytes: int
    scan_time_ms: int
    was_archive: bool
    num_findings: int

# -----------------------------
# Simple signature patterns
# -----------------------------

PATTERNS = {
    "email": re.compile(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"),
    "aws_access_key_id": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "private_key_pem": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "ssn_like": re.compile(rb"\b\d{3}-\d{2}-\d{4}\b"),
}

TEXT_EXTS = {".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".sql", ".ini", ".cfg", ".conf", ".md", ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh"}

# -----------------------------
# Utilities
# -----------------------------

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", flush=True)

def s3_client(region: str):
    return boto3.client("s3", config=Config(region_name=region, retries={"max_attempts": 10, "mode": "standard"}))

def is_probably_text_by_name(name: str) -> bool:
    ext = Path(name).suffix.lower()
    return ext in TEXT_EXTS or ext in DEFAULT_PRIORITY_EXTS

def prioritized(objects: List[ObjectRef]) -> List[ObjectRef]:
    def weight(o: ObjectRef) -> Tuple[int, int]:
        ext = Path(o.key).suffix.lower()
        pri = 0
        if ext in DEFAULT_PRIORITY_EXTS:
            pri = -2
        elif ext in SKIP_EARLY_EXTS:
            pri = 2
        else:
            pri = 0
        # smaller files earlier
        return (pri, o.size)
    return sorted(objects, key=weight)

def load_manifest(dev_mode: bool, dev_output: Path, s3c, results_bucket: Optional[str], manifest_key: str) -> Dict[str, dict]:
    if dev_mode:
        mf = dev_output / "manifest.json"
        if mf.exists():
            try:
                return json.loads(mf.read_text())
            except Exception:
                return {}
        return {}
    else:
        if not results_bucket:
            return {}
        try:
            obj = s3c.get_object(Bucket=results_bucket, Key=manifest_key)
            data = obj["Body"].read()
            return json.loads(data.decode("utf-8"))
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "NoSuchBucket"):
                return {}
            raise
        except Exception:
            return {}

def save_manifest(manifest: Dict[str, dict], dev_mode: bool, dev_output: Path, s3c, results_bucket: Optional[str], manifest_key: str) -> None:
    data = json.dumps(manifest, indent=2).encode("utf-8")
    if dev_mode:
        dev_output.mkdir(parents=True, exist_ok=True)
        (dev_output / "manifest.json").write_bytes(data)
    else:
        assert results_bucket, "results_bucket required in normal mode"
        s3c.put_object(Bucket=results_bucket, Key=manifest_key, Body=data, ContentType="application/json")

def manifest_key_for(obj: ObjectRef) -> str:
    return f"{obj.bucket}:{obj.key}"

def unchanged(obj: ObjectRef, manifest: Dict[str, dict]) -> bool:
    k = manifest_key_for(obj)
    m = manifest.get(k)
    if not m:
        return False
    return m.get("etag") == obj.etag and int(m.get("size", -1)) == obj.size and m.get("last_modified") == obj.last_modified

def remember(obj: ObjectRef, info: ObjectMetadata, manifest: Dict[str, dict]) -> None:
    manifest[manifest_key_for(obj)] = {
        "etag": obj.etag,
        "size": obj.size,
        "last_modified": obj.last_modified,
        "sha256": info.sha256,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "num_findings": info.num_findings,
    }

# -----------------------------
# S3 helpers
# -----------------------------

def list_buckets(s3c) -> List[str]:
    resp = s3c.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]

def list_objects(s3c, bucket: str, prefix: Optional[str] = None) -> Iterable[ObjectRef]:
    paginator = s3c.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix
    for page in paginator.paginate(**kwargs):
        for it in page.get("Contents", []):
            key = it["Key"]
            etag = it.get("ETag", "").strip('"') if it.get("ETag") else None
            size = int(it.get("Size", 0))
            last_modified = it.get("LastModified").astimezone(timezone.utc).isoformat() if it.get("LastModified") else None
            yield ObjectRef(bucket=bucket, key=key, etag=etag, size=size, last_modified=last_modified)

def head_object(s3c, bucket: str, key: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        resp = s3c.head_object(Bucket=bucket, Key=key)
        etag = resp.get("ETag", "").strip('"') if resp.get("ETag") else None
        content_type = resp.get("ContentType")
        return etag, content_type
    except ClientError:
        return None, None

def download_object_to_temp(s3c, bucket: str, key: str) -> Path:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, "wb") as f:
        s3c.download_fileobj(bucket, key, f)
    return Path(path)

# -----------------------------
# Scanning
# -----------------------------

def hash_file(path: Path) -> str:
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_archive(file_path: Path, workdir: Path) -> List[Path]:
    extracted: List[Path] = []
    ext = file_path.suffix.lower()
    if ext == ".zip":
        with zipfile.ZipFile(file_path, "r") as z:
            z.extractall(workdir)
            for n in z.namelist():
                p = workdir / n
                if p.is_file():
                    extracted.append(p)
    elif ext in {".tar", ".tgz"} or file_path.name.endswith(".tar.gz"):
        mode = "r:gz" if ext in {".tgz"} or file_path.name.endswith(".tar.gz") else "r:*"
        with tarfile.open(file_path, mode) as t:
            def is_within_directory(directory, target):
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                prefix = os.path.commonpath([abs_directory, abs_target])
                return prefix == abs_directory
            def safe_extract(tar, path="."):
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Unsafe path in tar archive")
                tar.extractall(path)
            safe_extract(t, workdir)
            for m in t.getmembers():
                p = workdir / m.name
                if p.is_file():
                    extracted.append(p)
    elif ext == ".gz":
        # single-member gzip -> strip .gz
        out = workdir / file_path.stem
        with gzip.open(file_path, "rb") as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
        if out.is_file():
            extracted.append(out)
    return extracted

def scan_bytes(blob: bytes, patterns=PATTERNS, context=32) -> List[Tuple[str, bytes, int, int, bytes]]:
    findings = []
    for name, rx in patterns.items():
        for m in rx.finditer(blob):
            s, e = m.span()
            snippet = blob[max(0, s - context): e + context]
            findings.append((name, m.group(0), s, e, snippet))
    return findings

def scan_file(path: Path) -> List[Tuple[str, bytes, int, int, bytes]]:
    try:
        # Only read up to a cap to avoid huge memory usage
        max_read = 10 * 1024 * 1024  # 10 MiB
        size = path.stat().st_size
        with open(path, "rb") as f:
            data = f.read(max_read if size > max_read else size)
        return scan_bytes(data)
    except Exception:
        return []

# -----------------------------
# Writers
# -----------------------------

class ResultsWriter:
    def __init__(self, dev_mode: bool, dev_output: Path, s3c, results_bucket: Optional[str], results_prefix: str):
        self.dev_mode = dev_mode
        self.dev_output = dev_output
        self.s3c = s3c
        self.results_bucket = results_bucket
        self.results_prefix = results_prefix.rstrip("/")
        self._metafile_local: Optional[Path] = None
        self._findingsfile_local: Optional[Path] = None
        self._lock = threading.Lock()
        self._init_files()

    def _init_files(self):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = f"scan_{ts}"
        if self.dev_mode:
            self.dev_output.mkdir(parents=True, exist_ok=True)
            self._metafile_local = self.dev_output / f"{base}_metadata.jsonl"
            self._findingsfile_local = self.dev_output / f"{base}_findings.jsonl"
            # create empty files
            self._metafile_local.write_text("")
            self._findingsfile_local.write_text("")
        else:
            # use temp local files then upload at the end
            self._metafile_local = Path(tempfile.mkstemp()[1])
            self._findingsfile_local = Path(tempfile.mkstemp()[1])

    def write_metadata(self, meta: ObjectMetadata):
        line = json.dumps(asdict(meta), ensure_ascii=False) + "\n"
        with self._lock:
            assert self._metafile_local is not None
            with open(self._metafile_local, "a", encoding="utf-8") as f:
                f.write(line)

    def write_findings(self, obj: ObjectRef, path_in_archive: Optional[str], findings: List[Tuple[str, bytes, int, int, bytes]]):
        with self._lock:
            assert self._findingsfile_local is not None
            with open(self._findingsfile_local, "a", encoding="utf-8") as f:
                for name, match, s, e, snippet in findings:
                    rec = {
                        "bucket": obj.bucket,
                        "key": obj.key,
                        "path_in_archive": path_in_archive,
                        "pattern": name,
                        "match": match.decode("utf-8", errors="replace"),
                        "start": s,
                        "end": e,
                        "context": snippet.decode("utf-8", errors="replace"),
                    }
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def finalize(self):
        if self.dev_mode:
            # already on disk for user
            return
        # upload to S3
        assert self.results_bucket, "results_bucket required in normal mode"
        ts = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%S")
        meta_key = f"{self.results_prefix}/{ts}/metadata.jsonl"
        findings_key = f"{self.results_prefix}/{ts}/findings.jsonl"
        with open(self._metafile_local, "rb") as f:
            self.s3c.upload_fileobj(f, self.results_bucket, meta_key, ExtraArgs={"ContentType":"application/json"})
        with open(self._findingsfile_local, "rb") as f:
            self.s3c.upload_fileobj(f, self.results_bucket, findings_key, ExtraArgs={"ContentType":"application/json"})
        # cleanup temp files
        with contextlib.suppress(Exception):
            os.remove(self._metafile_local)
            os.remove(self._findingsfile_local)

# -----------------------------
# Main scanning worker
# -----------------------------

def process_object(s3c, obj: ObjectRef, manifest: Dict[str, dict], writer: ResultsWriter) -> None:
    if unchanged(obj, manifest):
        return
    t0 = time.time()
    etag, content_type = head_object(s3c, obj.bucket, obj.key)
    # fallback to listing values
    if not obj.etag and etag:
        obj.etag = etag
    tmp = None
    sha = None
    num_findings_total = 0
    was_archive = False
    scanned_bytes = 0
    try:
        tmp = download_object_to_temp(s3c, obj.bucket, obj.key)
        sha = hash_file(tmp)
        scanned_bytes = min(tmp.stat().st_size, 10 * 1024 * 1024)
        ext = Path(obj.key).suffix.lower()

        # If archive, extract and scan contained files
        path_in_archive = None
        if ext in ARCHIVE_EXTS or obj.key.endswith(".tar.gz"):
            was_archive = True
            workdir = Path(tempfile.mkdtemp())
            try:
                extracted = extract_archive(tmp, workdir)
                for p in extracted:
                    findings = scan_file(p)
                    if findings:
                        path_in_archive = str(p.relative_to(workdir))
                        writer.write_findings(obj, path_in_archive, findings)
                        num_findings_total += len(findings)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
        else:
            # normal file
            if Path(obj.key).suffix.lower() in SKIP_EARLY_EXTS:
                # still read a small header to scan basic patterns
                with open(tmp, "rb") as f:
                    header = f.read(256 * 1024)
                fnds = scan_bytes(header)
            else:
                fnds = scan_file(tmp)
            if fnds:
                writer.write_findings(obj, None, fnds)
                num_findings_total += len(fnds)

    finally:
        if tmp:
            with contextlib.suppress(Exception):
                os.remove(tmp)

    t_ms = int((time.time() - t0) * 1000)
    meta = ObjectMetadata(
        bucket=obj.bucket,
        key=obj.key,
        etag=obj.etag,
        size=obj.size,
        last_modified=obj.last_modified,
        sha256=sha,
        content_type=content_type,
        scanned_bytes=scanned_bytes,
        scan_time_ms=t_ms,
        was_archive=was_archive,
        num_findings=num_findings_total,
    )
    writer.write_metadata(meta)
    remember(obj, meta, manifest)

# -----------------------------
# Argument parsing and entry
# -----------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="S3 scanner with archive support and dev mode.")
    ap.add_argument("--buckets", type=str, default=os.environ.get("SCANNER_BUCKETS", ""), help="Comma-separated bucket names to scan. If empty, scan all.")
    ap.add_argument("--prefix", type=str, default=os.environ.get("SCANNER_PREFIX", ""), help="Optional prefix filter.")
    ap.add_argument("--results-bucket", type=str, default=RESULTS_BUCKET_ENV, help="Results bucket for normal mode.")
    ap.add_argument("--results-prefix", type=str, default=RESULTS_PREFIX_ENV, help="Prefix in results bucket for outputs.")
    ap.add_argument("--manifest-key", type=str, default=MANIFEST_KEY_ENV, help="S3 key for manifest JSON.")
    ap.add_argument("--region", type=str, default=AWS_REGION_ENV, help="AWS region.")
    ap.add_argument("--concurrency", type=int, default=CONCURRENCY_ENV, help="Thread pool size.")
    ap.add_argument("--dev", action="store_true", help="Dev mode. Write outputs and manifest to a local folder.")
    ap.add_argument("--dev-output", type=str, default="./scanner_output", help="Local folder for dev mode outputs.")
    return ap.parse_args()

def main():
    args = parse_args()
    dev_mode = args.dev
    dev_output = Path(args.dev_output).resolve()
    s3c = s3_client(args.region)

    # Determine buckets
    if args.buckets.strip():
        buckets = [b.strip() for b in args.buckets.split(",") if b.strip()]
    else:
        buckets = list_buckets(s3c)

    # Protect against scanning results bucket itself
    results_bucket = None if dev_mode else (args.results_bucket or None)
    if not dev_mode and not results_bucket:
        raise SystemExit("results bucket required in normal mode. Use --results-bucket or RESULTS_BUCKET env var. Or pass --dev for local output.")

    # Load manifest
    manifest = load_manifest(dev_mode, dev_output, s3c, results_bucket, args.manifest_key)

    # Build object list
    all_objects: List[ObjectRef] = []
    for b in buckets:
        if not dev_mode and results_bucket and b == results_bucket:
            continue
        for o in list_objects(s3c, b, prefix=(args.prefix or None)):
            all_objects.append(o)

    # Prioritize
    objects = prioritized(all_objects)
    log(f"Planned objects. {len(objects)}")

    writer = ResultsWriter(dev_mode, dev_output, s3c, results_bucket, args.results_prefix)

    # Concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = [ex.submit(process_object, s3c, o, manifest, writer) for o in objects]
        for f in concurrent.futures.as_completed(futures):
            with contextlib.suppress(Exception):
                f.result()

    # Save outputs
    writer.finalize()
    save_manifest(manifest, dev_mode, dev_output, s3c, results_bucket, args.manifest_key)

    if dev_mode:
        log(f"Dev output written to. {dev_output}")

if __name__ == "__main__":
    main()
