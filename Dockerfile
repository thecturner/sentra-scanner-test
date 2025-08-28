# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Prevents Python from writing .pyc files and enables unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1         PYTHONUNBUFFERED=1         PIP_NO_CACHE_DIR=1

# System deps kept minimal on purpose
RUN apt-get update && apt-get install -y --no-install-recommends         ca-certificates curl tini         && rm -rf /var/lib/apt/lists/*

# App directory
WORKDIR /app

# Install Python deps first for caching
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

# Copy source into image
# Expecting scanner.py and/or simple_scanner.py at repo root
COPY . /app

# A small, flexible entrypoint that lets you choose the script and args at runtime
# SCANNER_SCRIPT defaults to scanner.py. Override with -e SCANNER_SCRIPT=simple_scanner.py
# SCANNER_ARGS can pass CLI args to the script if it supports any
ENV SCANNER_SCRIPT=scanner.py         SCANNER_ARGS=""

# Non-root for better security. Use 10001 as an arbitrary UID/GID.
RUN useradd -u 10001 -r -s /sbin/nologin appuser &&         chown -R appuser:appuser /app
USER appuser

# Ensure clean PID 1 and signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "python -u /app/${SCANNER_SCRIPT} ${SCANNER_ARGS}"]

# Copy the healthcheck helper into a known absolute path.
COPY healthcheck.sh /healthcheck.sh

# Docker runs this on a schedule and marks the container healthy or unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /healthcheck.sh
