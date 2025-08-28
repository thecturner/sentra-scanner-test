# Dockerizing **sentra-scanner-test**

This folder adds a container build that runs the scanner code inside a minimal Python image.

## Files included

- `Dockerfile` . Multi-stage-ready minimal image that installs Python deps and runs the scanner.
- `requirements.txt` . Python dependencies . currently only `boto3` and `botocore`.
- `.dockerignore` . Keeps the image lean . ignores build noise and Terraform state.
- `docker-compose.yml` . Local dev runner . passes AWS creds and runtime envs.
- `env.example` . Copy to `.env` to keep your local settings out of git.
- `healthcheck.sh` . Lightweight liveness. Zero network calls. No S3 access. Prove the container can load and compile your scanner code.
- `Makefile` . Handy build/run/push helpers.

## Quick start

1. Build.

   ```bash
   docker compose build
   ```

2. Run locally with your AWS creds.

   ```bash
   # Either export AWS_* in your shell or mount ~/.aws via compose
   docker compose up
   ```

3. Pick the script.

   ```bash
   # defaults to scanner.py . but you can switch:
   SCANNER_SCRIPT=simple_scanner.py docker compose up
   ```

4. Pass extra args if your script supports CLI flags.

   ```bash
   SCANNER_ARGS="--results-bucket my-bucket --threads 12" docker compose up
   ```

## Notes

- The container does not hardcode AWS credentials. Use env vars . IAM roles . or `~/.aws` profiles.
- `RESULTS_BUCKET` . `RESULTS_PREFIX` . `RESCAN_MANIFEST_KEY` are provided as conventional envs. If the current code uses different names . just map them via `SCANNER_ARGS` or adapt the script later.
- Keep images small. If you add heavy libs . consider adding build deps and then cleaning them up or switching to `python:3.11` build stage and copy the venv into `python:3.11-slim` runtime.
