#!/bin/zsh

set -euo pipefail

# Output file should not be used. Terraform reads from stdout.
# So we echo directly.

TMPDIR="${PWD}/unzipped_files"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# Hardcoded zip files
ZIPS=(
  "test-bucket-1-ct-us-east1-20250822.zip"
  "test-bucket-2-ct-us-east1-20250822.zip"
  "test-bucket-3-ct-us-east1-20250822.zip"
)

# Output as a single JSON object
echo '{'
first=1
for ZIP in "${ZIPS[@]}"; do
  bucket="${ZIP%.zip}"
  unzip -o "$ZIP" -d "${TMPDIR}/${bucket}" >/dev/null

  for file in "${TMPDIR}/${bucket}"/*; do
    filename=$(basename "$file")
    key="${bucket}/${filename}"
    # Escape double quotes and backslashes for JSON safety
    filepath=$(printf %q "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')
    if [[ $first -eq 0 ]]; then echo ','; fi
    echo "\"${key}\": \"${file}\""
    first=0
  done
done
echo '}'
