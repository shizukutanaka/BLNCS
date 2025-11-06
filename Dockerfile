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

# Production stage
FROM python:3.11-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    sqlite \
    tzdata

# Create user
RUN addgroup -g 1000 blncs && \
    adduser -D -u 1000 -G blncs blncs

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

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