#!/usr/bin/env sh
set -eu

# Try common app roots so we don't assume a specific WORKDIR.
SEARCH_PATHS="/app /usr/src/app /workspace /"

found_any=0
for name in scanner.py simple_scanner.py; do
  for d in $SEARCH_PATHS; do
    if [ -f "$d/$name" ]; then
      found_any=1
      break
    fi
  done
done

if [ "$found_any" -ne 1 ]; then
  echo "scanner.py/simple_scanner.py not found"
  exit 1
fi

# Compile without executing the app.
# Use 'find' to grab any copy we discovered in the first 3 levels.
PYFILES=$(find / -maxdepth 3 -type f \( -name "scanner.py" -o -name "simple_scanner.py" \) 2>/dev/null | tr '\n' ' ')
if [ -z "$PYFILES" ]; then
  echo "no python files discovered"
  exit 1
fi

python - <<'PY'
import sys, importlib, py_compile, shlex, os
files = shlex.split(os.environ.get("PYFILES",""))
if not files:
    print("no files passed")
    sys.exit(1)
for f in files:
    py_compile.compile(f, doraise=True)

# Core modules used for archive and text processing.
# Do not guess optional libs except boto3 which is commonly required for S3.
for m in ("re","json","gzip","zipfile","tarfile"):
    importlib.import_module(m)

try:
    importlib.import_module("boto3")
except Exception:
    # Optional. Presence depends on image contents.
    pass

print("healthcheck ok")
PY
