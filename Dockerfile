# BLNCS - Lightning Network Control System
# Multi-stage optimized production deployment
FROM python:3.11-alpine as builder

LABEL maintainer="BLNCS Team" \
      version="2.0.0" \
      description="Lightning Network Control System" \
      license="MIT"

# Set working directory
WORKDIR /app

# Install minimal build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    curl

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Security hardening of the Python tooling stack. The production image
# is scanned by a Trivy gate (CRITICAL/HIGH, fixed versions only), and
# the tooling below accounts for all of its Python findings:
# - The base image pins setuptools 79.0.1, whose vendored copies of
#   jaraco.context (5.3.0) and wheel (0.45.1) are below their fixed
#   versions. Upgrading setuptools/wheel also refreshes the vendored
#   copies (current setuptools vendors jaraco.context 6.1.0 and
#   wheel 0.46.3).
# - safety is a development/audit CLI that the application never
#   imports. It is also the only consumer of filelock and caps it at
#   <4.0, which blocks the filelock security fix (4.2.1), so safety
#   and filelock are removed from the image instead of shipping the
#   vulnerable filelock.
# - pip is a build-time tool and the production image does not need
#   it. It is removed last because the upgraded pip ships an SBOM
#   (pip/_vendor/bom.cdx.json) recording setuptools 70.3.0 (the
#   vendored pkg_resources), which the scanner reports as an
#   installed package.
RUN pip install --no-cache-dir --upgrade 'setuptools>=78.1.1' 'wheel>=0.46.2' && \
    pip uninstall -y safety safety-schemas filelock && \
    pip uninstall -y pip

# Production stage
FROM python:3.11-alpine

# Install runtime dependencies
# krb5-libs: the base image carries 1.22.2-r1 (pulled in by libtirpc,
# a Python runtime dependency) with known HIGH vulnerabilities. The
# version floor forces an upgrade to the fixed release in the Alpine
# repository; a plain `apk add krb5-libs` would keep the installed
# version because it already satisfies the unversioned constraint.
RUN apk add --no-cache \
    curl \
    sqlite \
    tzdata \
    'krb5-libs>=1.22.3-r0'

# Create user
RUN addgroup -g 1000 blncs && \
    adduser -D -u 1000 -G blncs blncs

# Copy Python packages from builder
# Remove the base image's site-packages first: COPY merges into the
# destination directory instead of replacing it, so without this the
# base image's own pip and the stale vendored dist-info entries of
# its setuptools 79.0.1 (jaraco.context 5.3.0, wheel 0.45.1) would
# survive next to the builder's upgraded copies and still be scanned.
RUN rm -rf /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# pip was removed in the builder; drop the base image's pip entry
# points that the merge-copy of /usr/local/bin leaves behind.
RUN rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=blncs:blncs blncs/ ./blncs/
COPY --chown=blncs:blncs blncs_main.py .
COPY --chown=blncs:blncs requirements.txt .

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/logs /app/config /app/backups && \
    chown -R blncs:blncs /app

# Switch to non-root user
USER blncs

# Environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BLNCS_ENV=production \
    PATH=/usr/local/bin:$PATH

# Expose API port
EXPOSE 8080

# Health check with improved logic
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f -s http://localhost:8080/health > /dev/null || exit 1

# Default command with proper server startup
CMD ["python3", "blncs_main.py", "server", "--host", "0.0.0.0", "--port", "8080"]